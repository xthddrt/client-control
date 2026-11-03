"""Live player coordinates and experimental native portal placement."""

import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import sys
import time

from PySide6.QtCore import QIODevice, QProcess, QProcessEnvironment, QSaveFile, Qt, QTimer
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDoubleSpinBox, QGridLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSpinBox, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_portal_movement", DIRECTORY / "try-native-reset.py")
movement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(movement)
portals = movement.portal_module
character = portals.character
LAUNCH_SPEC = importlib.util.spec_from_file_location("game_launcher", DIRECTORY / "launch-game.py")
launcher = importlib.util.module_from_spec(LAUNCH_SPEC)
LAUNCH_SPEC.loader.exec_module(launcher)
HOTKEY_SPEC = importlib.util.spec_from_file_location("global_hotkeys", DIRECTORY / "hotkeys.py")
hotkeys = importlib.util.module_from_spec(HOTKEY_SPEC)
HOTKEY_SPEC.loader.exec_module(hotkeys)
PROFILE = json.loads((DIRECTORY / "profile.json").read_text())
SPEED_FILE = DIRECTORY.parent / "native-speedhack-v13.speed"

# GRAP / NGS controls (telemetry shield v3 + core crash). The GUI runs as root.
RESEARCH_DIR = Path("/home/dingler/Desktop/NGS-GRAP-MapleStory-Research")
SHIELD_SCRIPT = RESEARCH_DIR / "workspace-position-research" / "shield-blackout-v3.sh"
SHIELD_STOP_SCRIPT = RESEARCH_DIR / "workspace-position-research" / "v3-stop.sh"
PARK_SCRIPT = RESEARCH_DIR / "workspace-position-research" / "vac-sprites.py"
MOB_COUNT_SCRIPT = RESEARCH_DIR / "workspace-position-research" / "mob-count.py"
MOB_COUNT_RETRY_SECONDS = 5.0
# count and pull-interval are injected at launch from the GUI spinboxes
# (see start_park); everything else is fixed. Defaults below are the
# proven-safe config from live Tests C/D: count=2 staggered 0.5s held with
# zero disconnects, where an unstaggered count=3 burst DC'd at ~4.4s.
PARK_DEFAULT_COUNT = 2
PARK_DEFAULT_INTERVAL = 0.5
PARK_ARGUMENTS = [
    "--y", "--hold-b", "--min-dist", "180",
    "--park", "0", "--park-gap", "12", "--park-hold", "1.0",
    "--fixed-anchor", "--view", "0", "0", "--control-stdin",
    # Original teleport vac (glide disabled for DC-escalation testing; enable with
    # "--glide", "500", "--glide-hz", "15" — see PM-68).
    "--log", "/tmp/park-dc.log",   # tees to /tmp/park-dc.log for DC forensics
]
CORE_CRASH_TOOL = RESEARCH_DIR / "continuation-artifacts" / "grap-core-crash.py"

# Hard-cleanup targets after a game crash. These are the real executable names.
# A process matches if EITHER its /proc/<pid>/comm (kernel-truncated to 15 chars,
# e.g. nexon_client.ex) matches, OR the basename of its argv[0] matches. The
# second path is required because nexon_client.exe is Chromium-based and renames
# its threads to CrBrowserMain/CrRendererMain/CrGpuMain/etc, so comm alone misses
# it; argv[0] still points at ...\nexon_client\nexon_client.exe.
KILL_EXE_NAMES = {
    "wineserver",
    "winedevice.exe",
    "nexon_client.exe",
    "nexon_runtime.exe",
    "maplestory.exe",
    "umu-run",
    "umu.exe",
    "grap-core64.aes",
}


def _basename(path):
    """Basename handling both POSIX and Windows separators."""
    return re.split(r"[\\/]", path.strip())[-1]


def find_processes_to_kill(name_by_pid, targets=KILL_EXE_NAMES, self_pid=None):
    """Return PIDs that match a target by comm or argv[0] basename.

    ``name_by_pid`` maps pid -> (comm, argv0). ``comm`` is the kernel's truncated
    thread name; ``argv0`` is the first cmdline field (may be empty for zombies).
    Matching is case-insensitive. ``comm`` is matched against each target's first
    15 characters to tolerate kernel truncation.
    """
    lowered = {name.lower() for name in targets}
    comm_prefixes = {name[:15] for name in lowered}
    victims = []
    for pid, value in name_by_pid.items():
        if pid == self_pid:
            continue
        comm, argv0 = value
        comm = comm.strip().lower()
        argv0_base = _basename(argv0).lower() if argv0 else ""
        if comm in comm_prefixes or argv0_base in lowered:
            victims.append(pid)
    return sorted(victims)


def read_process_names():
    """Return {pid: (comm, argv0)} for every readable process."""
    result = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", "replace") if raw else ""
        except OSError:
            argv0 = ""
        result[pid] = (comm, argv0)
    return result


def kill_signatures():
    """Substrings that uniquely identify any process in a game launch container.

    Every process from srt-bwrap/pv-adverb down to the wine services (services.exe,
    lsass.exe, explorer.exe) and the game itself carries the game's WINEPREFIX path
    and the speedhack preload library in its cmdline or environment. Matching on
    these catches the whole umu/pressure-vessel/wine tree, which a fixed list of
    executable names never could (wine renames processes to arbitrary .exe names).
    """
    sigs = [launcher.PRELOAD_LIBRARY]
    try:
        prefix = launcher.expand_user(PROFILE["game_launch"]["wine_prefix"]).resolve()
        sigs.append(str(prefix))
    except Exception:  # best-effort: fall back to preload-lib signature only
        pass
    return [s for s in sigs if s]


def _proc_session(entry):
    """Session id (SID) from /proc/<pid>/stat, or None. Robust to comm with spaces."""
    try:
        data = (entry / "stat").read_text()
        after = data[data.rfind(")") + 2:].split()
        # After comm: state(0) ppid(1) pgrp(2) session(3)
        return int(after[3])
    except (OSError, ValueError, IndexError):
        return None


def read_process_table(signatures=()):
    """Return {pid: {comm, argv0, blob, sid}} for every readable process.

    ``blob`` is cmdline + environ joined, searched for container signatures.
    ``environ`` is only read when signatures are supplied (root-only, larger).
    """
    table = {}
    want_env = bool(signatures)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            raw = b""
        argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", "replace") if raw else ""
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace")
        environ = ""
        if want_env:
            try:
                environ = (entry / "environ").read_bytes().replace(
                    b"\x00", b" ").decode("utf-8", "replace")
            except OSError:
                environ = ""
        table[pid] = {
            "comm": comm,
            "argv0": argv0,
            "blob": cmdline + " " + environ,
            "sid": _proc_session(entry),
        }
    return table


def find_kill_targets(table, signatures=(), targets=KILL_EXE_NAMES,
                      self_pid=None, self_sid=None):
    """Return every PID belonging to a game launch, for a full container teardown.

    A process is a *seed* if its comm/argv[0] matches a known executable name OR
    its cmdline/environ contains a container signature. Each seed is then expanded
    to every process sharing its session (SID), so the entire umu/pressure-vessel/
    wine tree dies together -- not just the leaf exe. The caller's own pid/session
    are never included.
    """
    lowered = {name.lower() for name in targets}
    comm_prefixes = {name[:15] for name in lowered}
    sigs = [s for s in signatures if s]
    seeds = set()
    for pid, info in table.items():
        if pid == self_pid:
            continue
        comm = info["comm"].strip().lower()
        argv0_base = _basename(info["argv0"]).lower() if info["argv0"] else ""
        if comm in comm_prefixes or argv0_base in lowered:
            seeds.add(pid)
        elif any(sig in info["blob"] for sig in sigs):
            seeds.add(pid)
    seed_sids = set()
    for pid in seeds:
        sid = table[pid].get("sid")
        if sid and sid != self_sid:
            seed_sids.add(sid)
    victims = set(seeds)
    for pid, info in table.items():
        if pid != self_pid and info.get("sid") in seed_sids:
            victims.add(pid)
    victims.discard(self_pid)
    return sorted(victims)

# Global (focus-independent) hotkeys. Single keys, no modifiers -- so pick keys
# that are not used elsewhere, since they fire regardless of which window is
# focused. key -> action id.
HOTKEY_MODIFIERS = []
HOTKEY_BINDINGS = [
    ("park", "pause", "Aggressive vac (toggle)"),
    ("overhead", "home", "Overhead polearm (toggle)"),
    ("speedtoggle", "scrolllock", "Speed 1x <-> 2x"),
    ("collision", "insert", "Collision MISS (toggle)"),
    ("panic", "end", "Panic: everything OFF + 1x"),
]
SHIELD_LOG = Path("/tmp/shield-v3.gui.log")
GRAP_CORE_COMM = "grap-core64.aes"
SHIELD_MATCH = "shield-blackout-v3.sh"


def _proc_is_zombie(entry):
    try:
        for line in (entry / "status").read_text().splitlines():
            if line.startswith("State:"):
                return "Z" in line.split(":", 1)[1]
    except OSError:
        pass
    return False


def _proc_comm_pid(comm):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() == comm and not _proc_is_zombie(entry):
                return int(entry.name)
        except OSError:
            continue
    return None


def core_pid():
    """PID of the live grap-core64 detection engine, or None if dead."""
    return _proc_comm_pid(GRAP_CORE_COMM)


def shield_pid():
    """PID of a running shield-blackout-v3 loop, or None."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if SHIELD_MATCH in cmdline:
            return int(entry.name)
    return None


def parse_speed(text):
    text = text.strip()
    if not re.fullmatch(r"\+?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", text):
        raise ValueError("Enter a positive multiplier, for example 1, 1.5, or 2.")
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("The speed multiplier must be finite and greater than zero.")
    return value


def read_speed():
    return parse_speed(SPEED_FILE.read_text(encoding="ascii"))


def write_speed(text):
    value = parse_speed(text)
    data = f"{value:.17g}\n".encode("ascii")
    output = QSaveFile(str(SPEED_FILE))
    if not output.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError(output.errorString())
    if output.write(data) != len(data):
        message = output.errorString()
        output.cancelWriting()
        raise OSError(message)
    if not output.commit():
        raise OSError(output.errorString())
    if read_speed() != value:
        raise RuntimeError("The speed setting changed before it could be verified.")
    return value


def read_live():
    pid = character.find_pid(PROFILE["process_name"])
    status = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
    )
    if status["State"].strip()[0] in "Tt":
        raise RuntimeError("Game is paused/traced. If a native call failed, restart rather than resume.")
    reader = character.Reader(pid)
    try:
        base, _ = character.find_image(reader, pid, PROFILE)
        for attempt in range(3):
            try:
                player = character.snapshot(reader, pid, base, PROFILE)
                try:
                    records = portals.portal_snapshot(reader, pid, base, PROFILE)
                    actor = int(player["character"], 0)
                    vector_offset = character.number(
                        PROFILE["character_offsets"]["vector_interface"]
                    )
                    if (
                        reader.qword(int(player["character_global"], 0)) != actor
                        or reader.qword(actor + vector_offset)
                        != int(player["vector_interface"], 0)
                    ):
                        raise character.SnapshotChanged(
                            "Character changed while reading the portal list."
                        )
                except character.SnapshotChanged:
                    raise
                except (OSError, RuntimeError, ValueError) as error:
                    records = {
                        "read_only": True,
                        "pid": pid,
                        "module_base": character.hexadecimal(base),
                        "manager": None,
                        "array": f"unavailable:{error}",
                        "slot_count": 0,
                        "null_slots": [],
                        "portals": [],
                        "type_2_edge_candidates": {"left": [], "right": []},
                        "selection_notice": f"Portals unavailable on this build: {error}",
                    }
                return player, records
            except character.SnapshotChanged:
                if attempt == 2:
                    raise
    finally:
        reader.close()


class PositionWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Player coordinates & portals")
        self.resize(1280, 820)
        self.player = None
        self.records = None
        self.context = None
        self.token = None
        self.table_token = None
        self.process = None
        self.overhead_process = None
        self.overhead_stopping = False
        self.overhead_detached = False
        self.overhead_buffer = ""
        self.atkspeed_process = None
        self.atkspeed_stopping = False
        self.atkspeed_detached = False
        self.atkspeed_buffer = ""
        self.pending_atkspeed_restart = False
        self.park_process = None
        self.park_stopping = False
        self.park_detached = False
        self.park_buffer = ""
        self.park_anchor = ""
        self.park_count = 0
        self.vac_process = None
        self.vac_stopping = False
        self.vac_detached = False
        self.vac_buffer = ""
        self.mobcount_process = None
        self.mobcount_pid = None
        self.mobcount_buffer = ""
        self.mobcount_last_start = 0.0
        self.pending_move = None
        self.closing = False
        self.last_error = None
        self.last_speed_error = None
        self.speed_initialized = False
        self.launch_process = None
        self.launch_log_path = None
        self.launch_error = None
        self.launch_available = False
        self.grap_processes = set()
        self.shield_log_offset = 0
        self.hotkey_listener = None
        container = QWidget()
        layout = QVBoxLayout(container)
        self.setCentralWidget(container)

        header = QHBoxLayout()
        self.status = QLabel("Connecting...")
        self.status.setWordWrap(True)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        self.launch_button = QPushButton("Launch game + speedhack")
        self.launch_button.clicked.connect(self.launch_game)
        self.kill_button = QPushButton("Kill game processes")
        self.kill_button.setToolTip(
            "Force-kill (SIGKILL) every wineserver, winedevice.exe, nexon_client, "
            "nexon_runtime, MapleStory.exe, umu-run and umu.exe process, so a hard "
            "crash can be restarted immediately."
        )
        self.kill_button.clicked.connect(self.kill_game_processes)
        header.addWidget(self.status, 1)
        header.addWidget(self.kill_button)
        header.addWidget(self.launch_button)
        header.addWidget(self.refresh_button)
        layout.addLayout(header)
        self.launch_status = QLabel()
        self.launch_status.setWordWrap(True)
        layout.addWidget(self.launch_status)
        root = layout
        reveal_row = QHBoxLayout()
        reveal_row.addWidget(QLabel("Show:"))
        self.show_grap_button = QPushButton("GRAP / NGS")
        self.show_nav_button = QPushButton("Coordinates && teleport")
        self.show_portals_button = QPushButton("Map portals")
        for button in (self.show_grap_button, self.show_nav_button, self.show_portals_button):
            button.setCheckable(True)
            reveal_row.addWidget(button)
        reveal_row.addStretch(1)
        root.addLayout(reveal_row)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setWidget(left_widget)
        left_scroll.setMinimumWidth(520)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(left_scroll)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([760, 520])
        root.addWidget(splitter, 1)

        speed_group = QGroupBox("Speedhack (existing v13 preload)")
        speed_layout = QGridLayout(speed_group)
        self.speed_value = QLineEdit()
        self.speed_value.setPlaceholderText("e.g. 1, 1.5, 2")
        self.speed_value.returnPressed.connect(self.apply_speed)
        self.speed_apply = QPushButton("Apply")
        self.speed_apply.clicked.connect(self.apply_speed)
        self.speed_normal = QPushButton("Normal (1x)")
        self.speed_normal.clicked.connect(self.normal_speed)
        self.speed_status = QLabel("Reading speed setting...")
        self.speed_status.setWordWrap(True)
        speed_group.setToolTip(
            "Use Launch game + speedhack to open standalone Nexon through UMU. Steam is not required. "
            "Scales only the game's CLOCK_MONOTONIC_RAW, not CLOCK_MONOTONIC or wineserver. "
            "Closing this GUI leaves the speed setting unchanged. "
            "Returning to 1x does not erase accumulated clock lead."
        )
        speed_layout.addWidget(QLabel("Multiplier"), 0, 0)
        speed_layout.addWidget(self.speed_value, 0, 1)
        speed_layout.addWidget(self.speed_apply, 0, 2)
        speed_layout.addWidget(self.speed_normal, 0, 3)
        speed_layout.addWidget(self.speed_status, 1, 0, 1, 4)

        grap_group = QGroupBox("GRAP / NGS controls (telemetry shield v3 + core crash)")
        grap_layout = QGridLayout(grap_group)
        self.shield_raise_button = QPushButton("Raise shield (v3)")
        self.shield_raise_button.setToolTip(
            "Start shield-blackout-v3.sh as root (sudo): in-world REJECT tcp-reset on NGS telemetry IPs."
        )
        self.shield_raise_button.clicked.connect(self.raise_shield)
        self.shield_lower_button = QPushButton("Lower shield (v3)")
        self.shield_lower_button.setToolTip(
            "Run v3-stop.sh (sudo SIGINT + teardown): removes the iptables REJECT rule and ipset."
        )
        self.shield_lower_button.clicked.connect(self.lower_shield)
        self.shield_status = QLabel("Shield v3: checking...")
        self.core_crash_button = QPushButton("Crash GRAP core")
        self.core_crash_button.setToolTip(
            "Install the fatal NtWriteFile code patch in grap-core64 (crashes the core; game keeps running)."
        )
        self.core_crash_button.clicked.connect(self.crash_core)
        self.core_status = QLabel("GRAP core: checking...")
        grap_layout.addWidget(self.shield_raise_button, 0, 0)
        grap_layout.addWidget(self.shield_lower_button, 0, 1)
        grap_layout.addWidget(self.shield_status, 0, 2)
        grap_layout.addWidget(self.core_crash_button, 1, 0)
        grap_layout.addWidget(self.core_status, 1, 2)

        coordinates = QGroupBox("Player coordinates")
        grid = QGridLayout(coordinates)
        grid.addWidget(QLabel(""), 0, 0)
        grid.addWidget(QLabel("X"), 0, 1)
        grid.addWidget(QLabel("Y"), 0, 2)
        self.current_x = QLineEdit()
        self.current_y = QLineEdit()
        self.current_x.setReadOnly(True)
        self.current_y.setReadOnly(True)
        grid.addWidget(QLabel("Live"), 1, 0)
        grid.addWidget(self.current_x, 1, 1)
        grid.addWidget(self.current_y, 1, 2)
        self.bounds = QLabel()
        grid.addWidget(self.bounds, 2, 0, 1, 3)
        nav_group = QGroupBox("Player coordinates && portal teleport")
        nav_layout = QVBoxLayout(nav_group)
        nav_layout.addWidget(coordinates)

        self.enable_movement = QCheckBox("Enable experimental portal teleportation")
        self.enable_movement.toggled.connect(self.movement_toggled)
        nav_layout.addWidget(self.enable_movement)
        self.stop_move_button = QPushButton("Cancel queued teleport")
        self.stop_move_button.clicked.connect(self.stop_move)
        nav_layout.addWidget(self.stop_move_button)
        caution = QLabel(
            "Stand still on solid ground with other debuggers detached. Move here calls the "
            "historical native position reset and places you near the selected portal; enter manually. "
            "This is experimental and may freeze or disconnect the game. A started native call "
            "cannot be safely cancelled; closing waits for the helper. No automatic retries."
        )
        caution.setWordWrap(True)
        nav_layout.addWidget(caution)
        combat_group = QGroupBox("Combat (overhead polearm + collision MISS)")
        combat_layout = QVBoxLayout(combat_group)
        self.enable_overhead = QCheckBox("Overhead-only polearm: basic, Power Strike, Slash Blast (experimental)")
        self.enable_overhead.toggled.connect(self.overhead_toggled)
        combat_layout.addWidget(self.enable_overhead)
        self.overhead_status = QLabel("Overhead override: off")
        combat_layout.addWidget(self.overhead_status)
        self.enable_collision_miss = QCheckBox("Collision MISS (experimental; ordinary contact path only)")
        self.enable_collision_miss.setToolTip(
            "Overrides the researched local monster-contact decision, not all incoming attacks. "
            "Earlier kicks remain unresolved; this does not guarantee server acceptance. "
            "Detach CE, ScyllaHide and other debuggers first."
        )
        self.enable_collision_miss.toggled.connect(self.override_configuration_changed)
        combat_layout.addWidget(self.enable_collision_miss)
        cycle_row = QHBoxLayout()
        self.cycle_collision_miss = QCheckBox("Repeat:")
        self.misses_before_normal = QSpinBox()
        self.misses_before_normal.setRange(1, 2**31 - 1)
        self.misses_before_normal.setValue(6)
        self.misses_before_normal.setKeyboardTracking(False)
        cycle_row.addWidget(self.cycle_collision_miss)
        cycle_row.addWidget(self.misses_before_normal)
        cycle_row.addWidget(QLabel("MISS, then one normal collision"), 1)
        combat_layout.addLayout(cycle_row)
        self.cycle_collision_miss.setToolTip(
            "Unchecked: continuous MISS. Checked: N misses, one native random collision, repeat. "
            "The normal collision can naturally miss. Changes and movement restart the cycle."
        )
        self.cycle_collision_miss.toggled.connect(self.override_configuration_changed)
        self.misses_before_normal.valueChanged.connect(self.override_configuration_changed)
        self.collision_status = QLabel("Collision MISS: off")
        combat_layout.addWidget(self.collision_status)
        atkspeed_group = QGroupBox("Attack-speed boost (animation-frame; no debugger)")
        atkspeed_layout = QGridLayout(atkspeed_group)
        atkspeed_group.setToolTip(
            "Shortens only the LOCAL actor's attack-animation frame timers for known polearm "
            "attack actions (basic swing, Power Strike, Slash Blast). Movement, jumps and other "
            "animations are untouched. Writes via process_vm_writev, so it needs no ptrace and "
            "coexists with the overhead override. Multiplies on top of the v13 speedhack "
            "(e.g. speed 2.0 x boost 1.5 = 3x attacks, movement stays 2x). Nothing to restore on stop."
        )
        self.enable_atkspeed = QCheckBox("Faster attacks (polearm basics, Power Strike, Slash Blast)")
        self.enable_atkspeed.toggled.connect(self.atkspeed_toggled)
        self.atkspeed_factor = QDoubleSpinBox()
        self.atkspeed_factor.setRange(1.0, 3.0)
        self.atkspeed_factor.setSingleStep(0.1)
        self.atkspeed_factor.setDecimals(1)
        self.atkspeed_factor.setValue(1.5)
        self.atkspeed_factor.setKeyboardTracking(False)
        self.atkspeed_factor.valueChanged.connect(self.atkspeed_config_changed)
        self.atkspeed_status = QLabel("Attack-speed boost: off")
        self.atkspeed_status.setWordWrap(True)
        atkspeed_layout.addWidget(self.enable_atkspeed, 0, 0)
        atkspeed_layout.addWidget(QLabel("Boost x"), 0, 1)
        atkspeed_layout.addWidget(self.atkspeed_factor, 0, 2)
        atkspeed_layout.addWidget(self.atkspeed_status, 1, 0, 1, 3)

        park_group = QGroupBox("Mob park (pull mobs to a fixed spot)")
        park_layout = QVBoxLayout(park_group)
        park_group.setToolTip(
            "Runs vac-sprites.py park mode as long as this is on. The park spot is your position "
            "and platform at the moment you enable it; walking away does not move it. Mobs are pulled "
            "one at a time, held ~1 s, then released and stay there server-side."
        )
        self.enable_park = QCheckBox("Park mobs at my current position (experimental)")
        self.enable_park.toggled.connect(self.park_toggled)
        self.park_status = QLabel("Mob park: off")
        self.park_status.setWordWrap(True)
        tune_row = QHBoxLayout()
        self.park_count_spin = QSpinBox()
        self.park_count_spin.setRange(1, 99)
        self.park_count_spin.setValue(PARK_DEFAULT_COUNT)
        self.park_count_spin.setToolTip(
            "Parallel holds: how many mobs are pulled at once. Higher = faster but more "
            "disconnect risk. Live-safe at 2-3 when staggered."
        )
        self.park_interval_spin = QDoubleSpinBox()
        self.park_interval_spin.setRange(0.0, 60.0)
        self.park_interval_spin.setSingleStep(0.1)
        self.park_interval_spin.setDecimals(2)
        self.park_interval_spin.setValue(PARK_DEFAULT_INTERVAL)
        self.park_interval_spin.setToolTip(
            "Stagger: minimum seconds between consecutive pulls. This was the key "
            "disconnect-safety factor. Lower = faster/riskier; raise it if you see DCs."
        )
        tune_row.addWidget(QLabel("Count"))
        tune_row.addWidget(self.park_count_spin)
        tune_row.addSpacing(12)
        tune_row.addWidget(QLabel("Stagger (s)"))
        tune_row.addWidget(self.park_interval_spin)
        tune_row.addStretch(1)
        park_layout.addWidget(self.enable_park)
        park_layout.addLayout(tune_row)
        self.park_snapfilter = QCheckBox(
            "Skip mobs owned by others (snap-back filter)"
        )
        self.park_snapfilter.setChecked(True)
        self.park_snapfilter.setToolTip(
            "On: mobs that snap back (owned by another client) are detected and skipped "
            "for a cooldown so holds aren't wasted on them. If throughput decays the longer "
            "park runs and a restart briefly fixes it, the filter is over-tagging your own "
            "patrolling mobs as foreign - turn it OFF to pull every candidate (watch the DC "
            "budget). Change takes effect on the next park start."
        )
        park_layout.addWidget(self.park_snapfilter)
        park_layout.addWidget(self.park_status)
        self.mob_count_label = QLabel("Mobs in client memory: -")
        self.mob_count_label.setToolTip(
            "CMob objects the client currently holds (read-only scan by mob-count.py). "
            "The client only loads mobs the server has streamed to it, so this is the "
            "pool park can pull from."
        )
        park_layout.addWidget(self.mob_count_label)

        vac_group = QGroupBox("Mob vac (aggressive full vacuum)")
        vac_layout = QGridLayout(vac_group)
        vac_group.setToolTip(
            "Runs vac-sprites.py in full-vacuum mode: holds EVERY nearby mob's controller-A "
            "(sprite) position at the player (and the server keyframe with Hold B) via "
            "process_vm_writev, no ptrace. This is the DC-escalation vehicle, distinct from the "
            "staggered one-at-a-time park above. Radius limits the pull to mobs within PX; Count "
            "pulls only the nearest N (blank = all). Hold B is the aggressive, historically "
            "DC-prone mode. Runs until you uncheck Enable vac; stops cleanly (waits for DETACHED)."
        )
        self.vac_radius = QLineEdit("1500")
        self.vac_radius.setPlaceholderText("px (blank = all)")
        self.vac_radius.setToolTip("Only pull mobs within this X distance of the player.")
        self.vac_count = QLineEdit()
        self.vac_count.setPlaceholderText("N (blank = all)")
        self.vac_count.setToolTip("Pull only the nearest N mobs (blank = every mob in range).")
        self.vac_hold_y = QCheckBox("Hold Y (cross-platform)")
        self.vac_hold_y.setChecked(True)
        self.vac_hold_y.setToolTip("Also hold the Y axis so mobs pull across platforms.")
        self.vac_hold_b = QCheckBox("Hold B (aggressive, DC-prone)")
        self.vac_hold_b.setChecked(True)
        self.vac_hold_b.setToolTip(
            "Also hold controller B (the server keyframe) at the forced spot. This is what "
            "historically trips the mob-move disconnect; uncheck for the safer sprite-only vac."
        )
        self.enable_vac = QCheckBox("Enable vac at my current position")
        self.enable_vac.toggled.connect(self.vac_toggled)
        self.vac_status = QLabel("Mob vac: off")
        self.vac_status.setWordWrap(True)
        vac_layout.addWidget(QLabel("Radius"), 0, 0)
        vac_layout.addWidget(self.vac_radius, 0, 1)
        vac_layout.addWidget(QLabel("Count"), 0, 2)
        vac_layout.addWidget(self.vac_count, 0, 3)
        vac_layout.addWidget(self.vac_hold_y, 1, 0, 1, 2)
        vac_layout.addWidget(self.vac_hold_b, 1, 2, 1, 2)
        vac_layout.addWidget(self.enable_vac, 2, 0, 1, 4)
        vac_layout.addWidget(self.vac_status, 3, 0, 1, 4)

        modifier_label = "+".join(
            hotkeys.MODIFIER_LABELS.get(name, name.title()) for name in HOTKEY_MODIFIERS
        )
        prefix = f"{modifier_label}+" if modifier_label else ""
        legend = "   ".join(
            f"{prefix}{hotkeys.key_label(key)} = {label}"
            for _, key, label in HOTKEY_BINDINGS
        )
        self.hotkey_legend = QLabel(f"Hotkeys: {legend}")
        self.hotkey_legend.setWordWrap(True)
        self.hotkey_status = QLabel("Global hotkeys: starting...")
        self.hotkey_legend.setToolTip("Global hotkeys work even when this window is not focused.")
        footer = QHBoxLayout()
        footer.addWidget(self.hotkey_legend, 1)
        footer.addWidget(self.hotkey_status)
        portal_header = QHBoxLayout()
        portal_header.addWidget(QLabel("Current map portals — duplicate names use distinct indices"), 1)
        self.show_spawns = QCheckBox("Show spawn points (type 0)")
        self.show_spawns.toggled.connect(self.refresh)
        portal_header.addWidget(self.show_spawns)
        self.portals_widget = QWidget()
        portals_layout = QVBoxLayout(self.portals_widget)
        portals_layout.setContentsMargins(0, 0, 0, 0)
        portals_layout.addLayout(portal_header)
        self.table = QTreeWidget()
        self.table.setHeaderLabels(["Index", "Label", "Type", "X", "Y", "Action"])
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.setMinimumHeight(240)
        portals_layout.addWidget(self.table, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(300)
        self.log.setPlaceholderText("Movement results and connection errors appear here.")
        right_layout.addWidget(self.portals_widget, 3)
        right_layout.addWidget(self.log, 2)
        for group in (speed_group, park_group, vac_group, combat_group, atkspeed_group, grap_group, nav_group):
            left_layout.addWidget(group)
        left_layout.addStretch(1)
        root.addLayout(footer)
        self.grap_group, self.nav_group = grap_group, nav_group
        for button, widget in (
            (self.show_grap_button, grap_group),
            (self.show_nav_button, nav_group),
            (self.show_portals_button, self.portals_widget),
        ):
            widget.setVisible(False)
            button.toggled.connect(widget.setVisible)
        self.timer = QTimer(self)
        self.timer.setInterval(750)
        self.timer.timeout.connect(self.refresh)
        self.refresh()
        self.timer.start()
        self.setup_hotkeys()

    def setup_hotkeys(self):
        if os.environ.get("POSITION_GUI_HOTKEYS", "1") != "1":
            self.hotkey_status.setText("Global hotkeys: disabled")
            return
        try:
            bindings = {
                action: hotkeys.KEY_CODES[key] for action, key, _ in HOTKEY_BINDINGS
            }
            listener = hotkeys.HotkeyListener(bindings, HOTKEY_MODIFIERS, self)
        except Exception as error:  # noqa: BLE001 - never let hotkeys break the GUI
            self.hotkey_status.setText(f"Global hotkeys: unavailable ({error})")
            return
        listener.activated.connect(self.handle_hotkey)
        listener.status.connect(self.hotkey_status.setText)
        self.hotkey_listener = listener
        listener.start()

    def handle_hotkey(self, action):
        if self.closing:
            return
        if action == "park":
            self.enable_vac.toggle()
        elif action == "overhead":
            self.enable_overhead.toggle()
        elif action == "collision":
            self.enable_collision_miss.toggle()
        elif action == "speedtoggle":
            self.toggle_speed()
        elif action == "panic":
            self.panic_all_off()
        self.log.appendPlainText(f"Hotkey: {action}")

    def toggle_speed(self):
        try:
            current = read_speed()
        except (OSError, ValueError):
            current = 1.0
        target = "1" if abs(current - 2.0) < 0.01 else "2"
        self.set_speed_multiplier(target)

    def set_speed_multiplier(self, text):
        if self.busy() or self.closing:
            self.log.appendPlainText(f"Speed {text}x hotkey ignored (busy).")
            return
        self.speed_value.setText(text)
        self.apply_speed()

    def panic_all_off(self):
        for checkbox in (
            self.enable_park, self.enable_collision_miss, self.enable_overhead,
            self.enable_atkspeed, self.enable_movement,
        ):
            if checkbox.isChecked():
                checkbox.setChecked(False)
        self.set_speed_multiplier("1")
        self.log.appendPlainText("PANIC: all experimental features off; speed set to 1x.")

    def busy(self):
        return self.process is not None or self.pending_move is not None

    def update_controls(self):
        available = self.player is not None and not self.busy() and not self.closing
        can_move = available and self.enable_movement.isChecked() and not self.overhead_stopping
        self.stop_move_button.setEnabled(self.pending_move is not None and not self.closing)
        self.refresh_button.setEnabled(not self.busy())
        self.enable_movement.setEnabled(not self.busy())
        self.show_spawns.setEnabled(not self.busy())
        for control in (self.speed_value, self.speed_apply, self.speed_normal):
            control.setEnabled(not self.busy() and not self.closing)
        self.launch_button.setEnabled(
            self.launch_available and not self.busy() and not self.closing
            and self.overhead_process is None
        )
        can_configure = (
            not self.busy() and not self.overhead_stopping and not self.closing
            and (self.player is not None or self.overhead_process is not None)
        )
        self.enable_overhead.setEnabled(can_configure)
        self.enable_collision_miss.setEnabled(can_configure)
        self.cycle_collision_miss.setEnabled(can_configure and self.enable_collision_miss.isChecked())
        self.misses_before_normal.setEnabled(
            can_configure and self.enable_collision_miss.isChecked()
            and self.cycle_collision_miss.isChecked()
        )
        atk_configurable = (
            not self.atkspeed_stopping and not self.closing
            and (self.player is not None or self.atkspeed_process is not None)
        )
        self.enable_atkspeed.setEnabled(atk_configurable)
        self.atkspeed_factor.setEnabled(atk_configurable)
        self.enable_park.setEnabled(
            not self.park_stopping and not self.closing
            and (self.player is not None or self.park_process is not None)
        )
        park_tunable = self.park_process is None and not self.park_stopping and not self.closing
        self.park_count_spin.setEnabled(park_tunable)
        self.park_interval_spin.setEnabled(park_tunable)
        self.park_snapfilter.setEnabled(park_tunable)
        self.enable_vac.setEnabled(
            not self.vac_stopping and not self.closing
            and (self.player is not None or self.vac_process is not None)
        )
        vac_tunable = self.vac_process is None and not self.vac_stopping and not self.closing
        self.vac_radius.setEnabled(vac_tunable)
        self.vac_count.setEnabled(vac_tunable)
        self.vac_hold_y.setEnabled(vac_tunable)
        self.vac_hold_b.setEnabled(vac_tunable)
        for index in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(index)
            button = self.table.itemWidget(item, 5)
            reason = "No current player/portal snapshot."
            if self.player is not None and self.records is not None:
                try:
                    movement.destination(self.player, self.records, button.property("portal_index"), self.token)
                except (RuntimeError, ValueError) as error:
                    reason = str(error)
                else:
                    reason = None
            button.setEnabled(can_move and reason is None)
            button.setToolTip(reason or "Teleport near this portal using the experimental native reset; enter manually.")

    def refresh_speed(self):
        try:
            value = read_speed()
        except (OSError, ValueError) as error:
            message = str(error)
            self.speed_status.setText(f"Speed setting unavailable: {message}")
            if message != self.last_speed_error:
                self.log.appendPlainText(f"Speed read failed: {message}")
                self.last_speed_error = message
            return
        self.last_speed_error = None
        self.speed_status.setText(f"Configured: {value:g}x; use Launch game + speedhack")
        if not self.speed_initialized:
            self.speed_value.setText(f"{value:.17g}")
            self.speed_initialized = True

    def apply_speed(self):
        if self.busy() or self.closing:
            return
        try:
            value = write_speed(self.speed_value.text())
        except (OSError, RuntimeError, ValueError) as error:
            message = str(error)
            self.log.appendPlainText(f"Speed change failed: {message}")
            self.refresh_speed()
            QMessageBox.warning(self, "Speed not applied", message)
            return
        self.speed_value.setText(f"{value:.17g}")
        self.log.appendPlainText(
            f"Speed setting saved: {value:g}x. The v13 preload reads it while the game runs."
        )
        self.refresh_speed()

    def normal_speed(self):
        self.speed_value.setText("1")
        self.apply_speed()

    def kill_game_processes(self):
        signatures = kill_signatures()
        try:
            self_sid = os.getsid(0)
        except OSError:
            self_sid = None
        victims = find_kill_targets(
            read_process_table(signatures), signatures,
            self_pid=os.getpid(), self_sid=self_sid,
        )
        if not victims:
            self.log.appendPlainText("Kill game processes: nothing matching is running.")
            QMessageBox.information(
                self, "Nothing to kill", "No matching game processes are running."
            )
            return
        preview = ", ".join(map(str, victims[:20])) + (" ..." if len(victims) > 20 else "")
        answer = QMessageBox.warning(
            self, "Kill game processes",
            f"Force-kill (SIGKILL) {len(victims)} process(es): {preview}?\n\n"
            "This tears down the ENTIRE game launch: every umu / pressure-vessel / "
            "wine process (srt-bwrap, pv-adverb, services.exe, explorer.exe, ...), "
            "nexon_client, nexon_runtime, MapleStory.exe, grap-core64.aes and umu-run. "
            "Matched by the game's WINEPREFIX + preload signature and expanded to the "
            "whole session, so no stragglers hang the next launch. Use after a crash.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        killed, failed = [], []
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
                killed.append(pid)
            except ProcessLookupError:
                killed.append(pid)
            except OSError as error:
                failed.append((pid, error))
        self.log.appendPlainText(
            f"Killed {len(killed)} game process(es): {', '.join(map(str, killed))}"
            if killed else "Kill game processes: none killed."
        )
        for pid, error in failed:
            self.log.appendPlainText(f"  could not kill {pid}: {error}")
        if failed:
            QMessageBox.warning(
                self, "Some processes survived",
                "Could not kill: " + ", ".join(f"{pid} ({err})" for pid, err in failed),
            )

    def launch_game(self):
        if self.busy() or self.closing or self.launch_process is not None or self.overhead_process is not None:
            return
        try:
            self.launch_process, self.launch_log_path = launcher.launch_game(PROFILE["game_launch"])
        except (OSError, RuntimeError, ValueError) as error:
            self.launch_error = f"Launch failed: {error}"
            self.log.appendPlainText(self.launch_error)
            QMessageBox.warning(self, "Game not launched", str(error))
        else:
            self.launch_error = None
            self.log.appendPlainText(
                "Starting standalone Nexon with the v13 preload; "
                "select the game there. Steam is not required."
            )
            self.log.appendPlainText(f"Private launcher output (may contain tokens): {self.launch_log_path}")
        self.refresh_launch()
        self.update_controls()

    def refresh_launch(self):
        self.launch_available = False
        if self.launch_process is not None:
            code = self.launch_process.poll()
            if code is not None:
                self.log.appendPlainText(f"GUI launch chain exited with code {code}.")
                if code:
                    self.launch_error = f"Launch chain exited with code {code}; private output: {self.launch_log_path}"
                self.launch_process = None
        try:
            processes = launcher.process_snapshot()
            if processes["game"]:
                loaded = all(launcher.preload_loaded(pid) for pid in processes["game"])
                message = (
                    "Game running; v13 speedhack preload detected."
                    if loaded else "Game running without v13 speedhack; relaunch using this GUI to enable it."
                )
            elif processes["launcher"]:
                loaded = all(launcher.preload_loaded(pid) for pid in processes["launcher"])
                message = (
                    "Nexon launcher running with v13; select the game there."
                    if loaded else "Launcher already running without v13; exit it fully (including the tray) "
                    "before launching through this GUI for speedhack."
                )
            elif self.launch_process is not None:
                message = "Starting MapleStory launcher..."
            else:
                message = self.launch_error or "Ready to launch standalone Nexon; Steam is not required."
            self.launch_available = (
                not processes["game"] and not processes["launcher"] and self.launch_process is None
            )
        except (OSError, RuntimeError, ValueError) as error:
            message = f"Launch status unavailable: {error}"
        self.launch_status.setText(message)

    def overhead_toggled(self, enabled):
        self.override_configuration_changed()

    def overrides_requested(self):
        return self.enable_overhead.isChecked() or self.enable_collision_miss.isChecked()

    def override_configuration_changed(self, *unused):
        if self.overhead_process is not None:
            self.stop_overhead()
        elif self.overrides_requested():
            self.start_overhead()
        self.update_controls()

    def clear_override_checkboxes(self):
        for checkbox in (self.enable_overhead, self.enable_collision_miss):
            previous = checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(previous)

    def start_overhead(self):
        if self.overhead_process is not None or self.busy() or self.closing or not self.overrides_requested():
            return
        if self.player is None:
            self.clear_override_checkboxes()
            self.overhead_status.setText("Overhead override: unavailable; no live player")
            self.collision_status.setText("Collision MISS: unavailable; no live player")
            return
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        arguments = [
            str(DIRECTORY / "overhead-attacks.py"), "--pid", str(self.player["pid"]),
            "--seconds", "0", "--control-stdin",
        ]
        if self.enable_overhead.isChecked():
            arguments.append("--force-overhead")
        if self.enable_collision_miss.isChecked():
            arguments.append("--force-collision-miss")
            if self.cycle_collision_miss.isChecked():
                arguments.extend(["--misses-before-normal", str(self.misses_before_normal.value())])
        process.setArguments(arguments)
        process.started.connect(self.overhead_started)
        process.readyReadStandardOutput.connect(self.read_overhead_output)
        process.finished.connect(self.overhead_finished)
        process.errorOccurred.connect(self.overhead_error)
        self.overhead_process = process
        self.overhead_buffer = ""
        self.overhead_detached = False
        self.overhead_stopping = False
        self.overhead_status.setText(
            "Overhead override: starting..." if self.enable_overhead.isChecked() else "Overhead override: off"
        )
        self.collision_status.setText(
            "Collision MISS: starting..." if self.enable_collision_miss.isChecked() else "Collision MISS: off"
        )
        self.update_controls()
        process.start()

    def overhead_started(self):
        if self.overhead_stopping:
            self.overhead_process.write(b"stop\n")

    def stop_overhead(self):
        if self.overhead_process is None or self.overhead_stopping:
            return
        self.overhead_stopping = True
        self.overhead_status.setText("Native overrides: stopping; waiting for detach...")
        self.collision_status.setText("Collision MISS: stopping; waiting for detach...")
        if self.overhead_process.state() == QProcess.ProcessState.Running:
            self.overhead_process.write(b"stop\n")
        self.update_controls()

    def read_overhead_output(self):
        if self.overhead_process is None:
            return
        self.overhead_buffer += bytes(
            self.overhead_process.readAllStandardOutput()
        ).decode(errors="replace")
        while "\n" in self.overhead_buffer:
            line, self.overhead_buffer = self.overhead_buffer.split("\n", 1)
            self.log.appendPlainText(line)
            if line.startswith("ARMED ") and not self.overhead_stopping:
                if self.enable_overhead.isChecked():
                    self.overhead_status.setText("Overhead override: active (polearm basics, Power Strike, Slash Blast)")
                if self.enable_collision_miss.isChecked():
                    self.collision_status.setText(
                        f"Collision MISS: active; {self.misses_before_normal.value()} MISS, one normal, repeat"
                        if self.cycle_collision_miss.isChecked() else "Collision MISS: active; continuous"
                    )
            elif line.startswith("COLLISION ") and not self.overhead_stopping:
                try:
                    outcome = json.loads(line.removeprefix("COLLISION "))
                    next_step = (
                        f"{outcome['remaining']} MISS before one normal"
                        if outcome["next_forced"] else "next collision: normal (can naturally miss)"
                    ) if outcome["miss_limit"] else "continuous"
                except (ValueError, KeyError, TypeError) as error:
                    self.log.appendPlainText(f"Invalid collision helper output: {error}")
                    self.clear_override_checkboxes()
                    self.stop_overhead()
                else:
                    self.collision_status.setText(f"Collision MISS: active; {next_step}")
            elif line.startswith("DETACHED:"):
                self.overhead_detached = True

    def overhead_error(self, error):
        if self.overhead_process is None:
            return
        self.log.appendPlainText(f"Native override helper error: {self.overhead_process.errorString()}")
        if error == QProcess.ProcessError.FailedToStart:
            self.overhead_finished(-1, QProcess.ExitStatus.NormalExit)

    def overhead_finished(self, exit_code, exit_status):
        self.read_overhead_output()
        process = self.overhead_process
        self.overhead_process = None
        if process is not None:
            process.deleteLater()
        if self.overhead_buffer:
            self.log.appendPlainText(self.overhead_buffer)
            self.overhead_buffer = ""
        detached = (
            exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit
            and self.overhead_detached
        )
        requested = self.overhead_stopping
        self.overhead_stopping = False
        if not detached or not requested:
            self.clear_override_checkboxes()
        self.overhead_status.setText(
            "Overhead override: off"
            if detached else "Overhead override: stopped with an error; check the log"
        )
        self.collision_status.setText(
            "Collision MISS: off"
            if detached else "Collision MISS: stopped with an error; check the log"
        )
        destination = self.pending_move
        self.pending_move = None
        if not detached:
            self.log.appendPlainText(
                "Native override shutdown was not verified. Any queued move was cancelled. "
                "If the game is paused, restart it rather than assuming it is safe to resume."
            )
        if destination is not None and detached and requested:
            self.launch_move(destination)
            return
        if self.closing and detached:
            QTimer.singleShot(0, self.close)
        else:
            if self.closing:
                self.closing = False
                self.timer.start()
            self.refresh()
            if detached and requested and self.overrides_requested():
                self.start_overhead()

    def atkspeed_toggled(self, enabled):
        if enabled:
            self.start_atkspeed()
        else:
            self.stop_atkspeed()
        self.update_controls()

    def atkspeed_config_changed(self, *unused):
        if self.atkspeed_process is not None and not self.atkspeed_stopping:
            self.stop_atkspeed()
            if self.enable_atkspeed.isChecked():
                self.pending_atkspeed_restart = True
        self.update_controls()

    def start_atkspeed(self):
        if self.atkspeed_process is not None or self.closing or not self.enable_atkspeed.isChecked():
            return
        if self.player is None:
            previous = self.enable_atkspeed.blockSignals(True)
            self.enable_atkspeed.setChecked(False)
            self.enable_atkspeed.blockSignals(previous)
            self.atkspeed_status.setText("Attack-speed boost: unavailable; no live player")
            return
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        process.setArguments([
            str(DIRECTORY / "atkspeed-frames.py"), "--pid", str(self.player["pid"]),
            "--factor", f"{self.atkspeed_factor.value():.1f}", "--control-stdin",
        ])
        process.readyReadStandardOutput.connect(self.read_atkspeed_output)
        process.finished.connect(self.atkspeed_finished)
        process.errorOccurred.connect(self.atkspeed_error)
        self.atkspeed_process = process
        self.atkspeed_buffer = ""
        self.atkspeed_detached = False
        self.atkspeed_stopping = False
        self.atkspeed_status.setText("Attack-speed boost: starting...")
        self.update_controls()
        process.start()

    def stop_atkspeed(self):
        if self.atkspeed_process is None or self.atkspeed_stopping:
            return
        self.atkspeed_stopping = True
        self.atkspeed_status.setText("Attack-speed boost: stopping...")
        if self.atkspeed_process.state() == QProcess.ProcessState.Running:
            self.atkspeed_process.write(b"stop\n")
        self.update_controls()

    def read_atkspeed_output(self):
        if self.atkspeed_process is None:
            return
        self.atkspeed_buffer += bytes(
            self.atkspeed_process.readAllStandardOutput()
        ).decode(errors="replace")
        while "\n" in self.atkspeed_buffer:
            line, self.atkspeed_buffer = self.atkspeed_buffer.split("\n", 1)
            self.log.appendPlainText(line)
            if line.startswith("ARMED ") and not self.atkspeed_stopping:
                self.atkspeed_status.setText(
                    f"Attack-speed boost: active x{self.atkspeed_factor.value():.1f} "
                    "(polearm basics, Power Strike, Slash Blast)"
                )
            elif line.startswith("DETACHED:"):
                self.atkspeed_detached = True

    def atkspeed_error(self, error):
        if self.atkspeed_process is None:
            return
        self.log.appendPlainText(f"Attack-speed helper error: {self.atkspeed_process.errorString()}")
        if error == QProcess.ProcessError.FailedToStart:
            self.atkspeed_finished(-1, QProcess.ExitStatus.NormalExit)

    def atkspeed_finished(self, exit_code, exit_status):
        self.read_atkspeed_output()
        process = self.atkspeed_process
        self.atkspeed_process = None
        if process is not None:
            process.deleteLater()
        if self.atkspeed_buffer:
            self.log.appendPlainText(self.atkspeed_buffer)
            self.atkspeed_buffer = ""
        clean = (
            exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit
            and self.atkspeed_detached
        )
        self.atkspeed_stopping = False
        restart = getattr(self, "pending_atkspeed_restart", False)
        self.pending_atkspeed_restart = False
        if not clean:
            previous = self.enable_atkspeed.blockSignals(True)
            self.enable_atkspeed.setChecked(False)
            self.enable_atkspeed.blockSignals(previous)
            self.atkspeed_status.setText("Attack-speed boost: stopped with an error; check the log")
        else:
            self.atkspeed_status.setText("Attack-speed boost: off")
        if clean and restart and self.enable_atkspeed.isChecked() and not self.closing:
            self.start_atkspeed()
        self.update_controls()

    def park_toggled(self, enabled):
        if enabled:
            self.start_park()
        else:
            self.stop_park()
        self.update_controls()

    def start_park(self):
        if self.park_process is not None or self.closing or not self.enable_park.isChecked():
            return
        if self.player is None:
            previous = self.enable_park.blockSignals(True)
            self.enable_park.setChecked(False)
            self.enable_park.blockSignals(previous)
            self.park_status.setText("Mob park: unavailable; no live player")
            return
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        environment.insert("PYTHONUNBUFFERED", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        count = self.park_count_spin.value()
        interval = self.park_interval_spin.value()
        tuning = ["--count", str(count), "--pull-interval", f"{interval:.2f}"]
        if not self.park_snapfilter.isChecked():
            tuning.append("--no-foreign-skip")
        process.setArguments([str(PARK_SCRIPT), str(self.player["pid"]), "86400", *tuning, *PARK_ARGUMENTS])
        process.readyReadStandardOutput.connect(self.read_park_output)
        process.finished.connect(self.park_finished)
        process.errorOccurred.connect(self.park_error)
        self.park_process = process
        self.park_buffer = ""
        self.park_detached = False
        self.park_stopping = False
        self.park_anchor = ""
        self.park_count = 0
        self.park_status.setText("Mob park: starting...")
        self.update_controls()
        process.start()

    def stop_park(self):
        if self.park_process is None or self.park_stopping:
            return
        self.park_stopping = True
        self.park_status.setText("Mob park: stopping...")
        if self.park_process.state() == QProcess.ProcessState.Running:
            self.park_process.write(b"stop\n")
        self.update_controls()

    def read_park_output(self):
        if self.park_process is None:
            return
        self.park_buffer += bytes(self.park_process.readAllStandardOutput()).decode(errors="replace")
        while "\n" in self.park_buffer:
            line, self.park_buffer = self.park_buffer.split("\n", 1)
            if line.startswith("t="):
                continue
            self.log.appendPlainText(line)
            if line.startswith("ARMED "):
                match = re.search(r"anchor=\(([-\d]+),([-\d]+)\)", line)
                self.park_anchor = f" at ({match.group(1)}, {match.group(2)})" if match else ""
            elif "PARKED #" in line:
                self.park_count += 1
            elif line.startswith("DETACHED:"):
                self.park_detached = True
                continue
            else:
                continue
            if not self.park_stopping:
                self.park_status.setText(f"Mob park: active{self.park_anchor}; parked {self.park_count}")

    def park_error(self, error):
        if self.park_process is None:
            return
        self.log.appendPlainText(f"Mob park helper error: {self.park_process.errorString()}")
        if error == QProcess.ProcessError.FailedToStart:
            self.park_finished(-1, QProcess.ExitStatus.NormalExit)

    def park_finished(self, exit_code, exit_status):
        self.read_park_output()
        process = self.park_process
        self.park_process = None
        if process is not None:
            process.deleteLater()
        if self.park_buffer:
            self.log.appendPlainText(self.park_buffer)
            self.park_buffer = ""
        clean = exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit and self.park_detached
        self.park_stopping = False
        if not clean:
            previous = self.enable_park.blockSignals(True)
            self.enable_park.setChecked(False)
            self.enable_park.blockSignals(previous)
            self.park_status.setText("Mob park: stopped with an error; check the log")
        else:
            self.park_status.setText(f"Mob park: off (parked {self.park_count})")
        self.update_controls()

    def vac_toggled(self, enabled):
        if enabled:
            self.start_vac()
        else:
            self.stop_vac()
        self.update_controls()

    def start_vac(self):
        if self.vac_process is not None or self.closing or not self.enable_vac.isChecked():
            return
        if self.player is None:
            previous = self.enable_vac.blockSignals(True)
            self.enable_vac.setChecked(False)
            self.enable_vac.blockSignals(previous)
            self.vac_status.setText("Mob vac: unavailable; no live player")
            return
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        environment.insert("PYTHONUNBUFFERED", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        arguments = [str(PARK_SCRIPT), str(self.player["pid"]), "86400", "--control-stdin"]
        if self.vac_hold_y.isChecked():
            arguments.append("--y")
        if self.vac_hold_b.isChecked():
            arguments.append("--hold-b")
        radius = self.vac_radius.text().strip()
        if radius:
            arguments += ["--radius", radius]
        count = self.vac_count.text().strip()
        if count:
            arguments += ["--count", count]
        process.setArguments(arguments)
        process.readyReadStandardOutput.connect(self.read_vac_output)
        process.finished.connect(self.vac_finished)
        process.errorOccurred.connect(self.vac_error)
        self.vac_process = process
        self.vac_buffer = ""
        self.vac_detached = False
        self.vac_stopping = False
        self.vac_status.setText("Mob vac: starting...")
        self.update_controls()
        process.start()

    def stop_vac(self):
        if self.vac_process is None or self.vac_stopping:
            return
        self.vac_stopping = True
        self.vac_status.setText("Mob vac: stopping; waiting for detach...")
        if self.vac_process.state() == QProcess.ProcessState.Running:
            self.vac_process.write(b"stop\n")
        self.update_controls()

    def read_vac_output(self):
        if self.vac_process is None:
            return
        self.vac_buffer += bytes(self.vac_process.readAllStandardOutput()).decode(errors="replace")
        while "\n" in self.vac_buffer:
            line, self.vac_buffer = self.vac_buffer.split("\n", 1)
            if line.startswith("t="):
                continue
            self.log.appendPlainText(line)
            if line.startswith("VAC pid="):
                if not self.vac_stopping:
                    self.vac_status.setText("Mob vac: active")
            elif line.startswith("DETACHED:"):
                self.vac_detached = True

    def vac_error(self, error):
        if self.vac_process is None:
            return
        self.log.appendPlainText(f"Mob vac helper error: {self.vac_process.errorString()}")
        if error == QProcess.ProcessError.FailedToStart:
            self.vac_finished(-1, QProcess.ExitStatus.NormalExit)

    def vac_finished(self, exit_code, exit_status):
        self.read_vac_output()
        process = self.vac_process
        self.vac_process = None
        if process is not None:
            process.deleteLater()
        if self.vac_buffer:
            self.log.appendPlainText(self.vac_buffer)
            self.vac_buffer = ""
        clean = exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit and self.vac_detached
        self.vac_stopping = False
        if not clean:
            previous = self.enable_vac.blockSignals(True)
            self.enable_vac.setChecked(False)
            self.enable_vac.blockSignals(previous)
            self.vac_status.setText("Mob vac: stopped with an error; check the log")
        else:
            self.vac_status.setText("Mob vac: off")
        if self.closing:
            QTimer.singleShot(0, self.close)
        self.update_controls()

    def movement_toggled(self, enabled):
        if enabled:
            answer = QMessageBox.warning(
                self, "Experimental portal teleportation",
                "This calls the game's native position reset, using the old portal-placement method. "
                "It can freeze or disconnect the game and is not guaranteed to be accepted by the server. "
                "Stand still on solid ground and detach other debuggers first.\n\n"
                "A started native call cannot be cancelled safely. If it fails and leaves the game paused, "
                "restart rather than resume. Entering a portal remains manual. Enable teleportation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.enable_movement.setChecked(False)
        self.update_controls()

    def refresh(self):
        self.refresh_speed()
        self.refresh_launch()
        self.update_grap_status()
        if self.busy():
            return
        try:
            player, records = read_live()
        except (OSError, RuntimeError, ValueError) as error:
            message = str(error)
            self.player = None
            self.records = None
            self.token = None
            self.table_token = None
            self.current_x.clear()
            self.current_y.clear()
            self.table.clear()
            self.bounds.setText("")
            self.status.setText(f"Unavailable: {message}")
            if message != self.last_error:
                self.log.appendPlainText(f"Read failed: {message}")
                self.last_error = message
            self.update_controls()
            return
        token = portals.snapshot_token(records)
        context = (player["pid"], player["controller"], records["array"])
        changed_context = self.context != context
        self.player, self.records = player, records
        self.current_x.setText(str(player["cached_x"]["value"]))
        self.current_y.setText(str(player["cached_y"]["value"]))
        if changed_context:
            self.log.appendPlainText("New character/map context: portal destinations refreshed.")
        displayed = [
            portal for portal in records["portals"]
            if self.show_spawns.isChecked() or portal["type"] != 0
        ]
        table_token = (token, self.show_spawns.isChecked())
        if table_token != self.table_token:
            self.table.clear()
            for portal in displayed:
                item = QTreeWidgetItem([
                    str(portal["index"]), portal["name"] or "(unnamed)",
                    "Spawn point (0)" if portal["type"] == 0 else str(portal["type"]),
                    str(portal["x"]), str(portal["y"]), "",
                ])
                self.table.addTopLevelItem(item)
                button = QPushButton("Move here" if portal["type"] != 0 else "View only")
                button.setProperty("portal_index", portal["index"])
                button.clicked.connect(
                    lambda checked=False, index=portal["index"], expected=token: self.move_portal(index, expected)
                )
                self.table.setItemWidget(item, 5, button)
            for column in range(5):
                self.table.resizeColumnToContents(column)
        self.table_token = table_token
        self.context, self.token = context, token
        self.last_error = None
        ground = player["foothold"]
        state = "grounded" if ground["has_foothold_pointer"] else "airborne"
        hidden = len(records["portals"]) - len(displayed)
        description = (
            f"{len(displayed)} records (including spawn points)"
            if self.show_spawns.isChecked() else f"{len(displayed)} portals · {hidden} spawn points hidden"
        )
        self.status.setText(f"Connected · PID {player['pid']} · {state} · {description}")
        if ground["has_foothold_pointer"]:
            points = ground["endpoints"]
            self.bounds.setText(
                f"Current foothold: ({points['x1']}, {points['y1']}) → "
                f"({points['x2']}, {points['y2']}). Portal targets are checked against controller bounds."
            )
        else:
            self.bounds.setText("Airborne — wait until grounded before moving.")
        self.ensure_mob_count(player["pid"])
        self.update_controls()

    def ensure_mob_count(self, pid):
        if self.closing:
            return
        if self.mobcount_process is not None:
            if self.mobcount_pid == pid:
                return
            self.stop_mob_count()
        now = time.monotonic()
        if now - self.mobcount_last_start < MOB_COUNT_RETRY_SECONDS:
            return
        self.mobcount_last_start = now
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        environment.insert("PYTHONUNBUFFERED", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        process.setArguments([str(MOB_COUNT_SCRIPT), str(pid)])
        process.readyReadStandardOutput.connect(self.read_mob_count_output)
        process.finished.connect(self.mob_count_finished)
        self.mobcount_process = process
        self.mobcount_pid = pid
        self.mobcount_buffer = ""
        process.start()

    def read_mob_count_output(self):
        process = self.mobcount_process
        if process is None:
            return
        self.mobcount_buffer += bytes(process.readAllStandardOutput()).decode(errors="replace")
        while "\n" in self.mobcount_buffer:
            line, self.mobcount_buffer = self.mobcount_buffer.split("\n", 1)
            match = re.match(r"MOBS (\d+)(?: xmin=(-?\d+) xmax=(-?\d+))?", line)
            if not match:
                if line.strip():
                    self.log.appendPlainText(f"mob-count: {line}")
                continue
            text = f"Mobs in client memory: {match.group(1)}"
            if match.group(2) is not None:
                text += f"  (X {match.group(2)} .. {match.group(3)})"
            self.mob_count_label.setText(text)

    def mob_count_finished(self, *_):
        process = self.mobcount_process
        self.mobcount_process = None
        self.mobcount_pid = None
        if process is not None:
            process.deleteLater()
        self.mob_count_label.setText("Mobs in client memory: -")

    def stop_mob_count(self):
        process = self.mobcount_process
        if process is None:
            return
        self.mobcount_process = None
        self.mobcount_pid = None
        try:
            process.finished.disconnect(self.mob_count_finished)
        except (RuntimeError, TypeError):
            pass
        process.write(b"stop\n")
        process.closeWriteChannel()
        if not process.waitForFinished(1500):
            process.kill()
            process.waitForFinished(1000)
        process.deleteLater()
        self.mob_count_label.setText("Mobs in client memory: -")

    def ready(self):
        if self.busy() or self.closing or not self.enable_movement.isChecked() or self.player is None:
            return False
        if not self.player["foothold"]["has_foothold_pointer"]:
            QMessageBox.warning(self, "Move not started", "Stand still on solid ground first.")
            return False
        return True

    def move_portal(self, index, token):
        if not self.ready():
            return
        if token != self.token:
            QMessageBox.warning(self, "Stale portal", "The portal list changed. Choose a current row.")
            return
        try:
            movement.destination(self.player, self.records, index, token)
        except (RuntimeError, ValueError) as error:
            self.log.appendPlainText(f"Portal teleport not started: {error}")
            return
        self.start_move([
            "--portal-index", str(index), "--expected-portal-token", token,
        ])

    def start_move(self, destination):
        arguments = [
            str(DIRECTORY / "try-native-reset.py"),
            "--pid", str(self.player["pid"]),
            "--expected-controller", self.player["controller"],
            *destination, "--initial-only", "--execute",
        ]
        if self.overhead_process is not None:
            self.pending_move = arguments
            self.log.appendPlainText("Stopping native overrides before portal teleportation...")
            self.stop_overhead()
            self.update_controls()
            return
        self.launch_move(arguments)

    def launch_move(self, arguments):
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(sys.executable)
        process.setArguments(arguments)
        process.readyReadStandardOutput.connect(self.read_process_output)
        process.finished.connect(self.move_finished)
        process.errorOccurred.connect(self.process_error)
        self.process = process
        self.status.setText("Experimental portal placement in progress; waiting for native return.")
        self.log.appendPlainText("Starting the historical native portal reset; entering remains manual.")
        self.update_controls()
        process.start()

    def stop_move(self):
        self.pending_move = None
        self.update_controls()

    def read_process_output(self):
        if self.process is not None:
            data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
            self.log.moveCursor(QTextCursor.MoveOperation.End)
            self.log.insertPlainText(data)
            scrollbar = self.log.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def process_error(self, error):
        if error == QProcess.ProcessError.FailedToStart and self.process is not None:
            message = self.process.errorString()
            self.log.appendPlainText(f"Cannot start movement helper: {message}")
            self.move_finished(-1, QProcess.ExitStatus.NormalExit)

    def move_finished(self, exit_code, exit_status):
        self.read_process_output()
        process = self.process
        self.process = None
        if process is not None:
            process.deleteLater()
        succeeded = exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit
        self.log.appendPlainText(
            "Initial portal placement reached the physics body; enter manually. Server acceptance is unverified."
            if succeeded else "Portal placement was not verified. See the helper output above; restart if the game is paused."
        )
        if self.closing:
            QTimer.singleShot(0, self.close)
            return
        self.refresh()
        if succeeded and self.overrides_requested():
            self.start_overhead()
        if not succeeded:
            self.clear_override_checkboxes()
            self.log.appendPlainText(
                "No automatic retry will be made. Check the actual character/map before continuing."
            )

    def _grap_log(self, tag, proc):
        data = bytes(proc.readAllStandardOutput()).decode(errors="replace")
        for line in data.splitlines():
            self.log.appendPlainText(f"{tag}{line}")

    def _start_grap_process(self, program, arguments, *, tag, on_finished=None):
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")
        process.setProcessEnvironment(environment)
        process.setProgram(program)
        process.setArguments(arguments)
        process.readyReadStandardOutput.connect(lambda p=process, t=tag: self._grap_log(t, p))
        process.errorOccurred.connect(
            lambda error, p=process, t=tag: self.log.appendPlainText(f"{t}error: {p.errorString()}")
        )

        def finished(code, status, p=process, cb=on_finished, t=tag):
            self._grap_log(t, p)
            self.grap_processes.discard(p)
            if cb is not None:
                cb(code, status)
            p.deleteLater()
            self.update_grap_status()

        process.finished.connect(finished)
        self.grap_processes.add(process)
        process.start()
        return process

    def raise_shield(self):
        if self.closing:
            return
        if shield_pid() is not None:
            self.log.appendPlainText("[shield] already running.")
            self.update_grap_status()
            return
        # Run detached (setsid) so closing the GUI never kills the shield or
        # orphans its iptables rule; output is tailed from SHIELD_LOG.
        try:
            SHIELD_LOG.write_text("")
        except OSError as error:
            self.log.appendPlainText(f"[shield] cannot reset log: {error}")
        self.shield_log_offset = 0
        command = "exec {script} {proc} 1 >> {log} 2>&1".format(
            script=shlex.quote(str(SHIELD_SCRIPT)),
            proc=shlex.quote(PROFILE["process_name"]),
            log=shlex.quote(str(SHIELD_LOG)),
        )
        self.log.appendPlainText("[shield] raising v3...")
        ok, _pid = QProcess.startDetached("setsid", ["bash", "-c", command])
        if not ok:
            self.log.appendPlainText("[shield] failed to start.")
        self.update_grap_status()

    def lower_shield(self):
        if self.closing:
            return
        self.log.appendPlainText("[shield] lowering v3 (SIGINT + teardown)...")
        self._start_grap_process("bash", [str(SHIELD_STOP_SCRIPT)], tag="[shield-stop] ")
        self.update_grap_status()

    def crash_core(self):
        if self.closing:
            return
        if core_pid() is None:
            self.log.appendPlainText("[crash] GRAP core already dead.")
            self.update_grap_status()
            return
        answer = QMessageBox.warning(
            self, "Crash GRAP core",
            "This installs a fatal code patch in grap-core64's ntdll NtWriteFile stub, "
            "crashing the core while the game keeps running.\n\n"
            "The crash evades the liveness auditor, so you stay in-session — but changing "
            "channel or re-logging will then require relaunching the client.\n\n"
            "Crash the GRAP core now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.log.appendPlainText("[crash] arming grap-core-crash.py (arm --go)...")
        self._start_grap_process(
            sys.executable, [str(CORE_CRASH_TOOL), "arm", "--go"], tag="[crash] ",
        )

    def _tail_shield_log(self):
        try:
            size = SHIELD_LOG.stat().st_size
        except OSError:
            return
        if size < self.shield_log_offset:
            self.shield_log_offset = 0
        if size == self.shield_log_offset:
            return
        try:
            with SHIELD_LOG.open("r", errors="replace") as handle:
                handle.seek(self.shield_log_offset)
                chunk = handle.read()
                self.shield_log_offset = handle.tell()
        except OSError:
            return
        for line in chunk.splitlines():
            self.log.appendPlainText(f"[shield] {line}")

    def update_grap_status(self):
        self._tail_shield_log()
        core = core_pid()
        self.core_status.setText(
            f"GRAP core: ALIVE (PID {core})" if core is not None else "GRAP core: dead"
        )
        self.core_crash_button.setEnabled(core is not None and not self.closing)
        running = shield_pid() is not None
        self.shield_status.setText("Shield v3: RUNNING" if running else "Shield v3: stopped")
        self.shield_raise_button.setEnabled(not running and not self.closing)
        self.shield_lower_button.setEnabled(running and not self.closing)

    def closeEvent(self, event):
        self.stop_mob_count()
        if self.hotkey_listener is not None:
            self.hotkey_listener.stop()
            self.hotkey_listener.wait(1000)
            self.hotkey_listener = None
        if self.atkspeed_process is not None:
            self.stop_atkspeed()
        if self.park_process is not None:
            self.stop_park()
        if self.busy():
            self.closing = True
            self.stop_move()
            if self.overhead_process is not None:
                self.stop_overhead()
            if self.vac_process is not None:
                self.stop_vac()
            event.ignore()
            return
        self.timer.stop()
        if self.overhead_process is not None or self.vac_process is not None:
            self.closing = True
            if self.overhead_process is not None:
                self.stop_overhead()
            if self.vac_process is not None:
                self.stop_vac()
            event.ignore()
            return
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = PositionWindow()
    window.show()
    QTimer.singleShot(0, lambda: print("GUI ready; portal teleportation, overhead and collision MISS start disabled.", flush=True))
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
