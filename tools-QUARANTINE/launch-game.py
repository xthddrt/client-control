"""Validated standalone UMU launch support for the saved game profile."""

import os
from pathlib import Path
import re
import subprocess
import tempfile


DIRECTORY = Path(__file__).resolve().parent
PRELOAD_LIBRARY = str(DIRECTORY.parent / "native-speedhack-v13.so")


def expand_user(value):
    return Path(value).expanduser()


def _basename(value):
    return re.split(r"[\\/]", value.strip())[-1].lower()


def process_snapshot():
    result = {"game": [], "launcher": []}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            comm = (entry / "comm").read_text().strip().lower()
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv0 = _basename(raw.split(b"\0", 1)[0].decode(errors="replace")) if raw else ""
        names = {comm, argv0}
        if "maplestory.exe" in names:
            result["game"].append(int(entry.name))
        if "nexon_launcher.exe" in names or "nexon_client.exe" in names:
            result["launcher"].append(int(entry.name))
    result["game"].sort()
    result["launcher"].sort()
    return result


def preload_loaded(pid):
    try:
        maps = Path(f"/proc/{pid}/maps").read_text(errors="replace")
    except FileNotFoundError:
        return False
    return any(Path(PRELOAD_LIBRARY).name in line for line in maps.splitlines())


def launch_game(config):
    processes = process_snapshot()
    if processes["game"] or processes["launcher"]:
        raise RuntimeError("Exit the running game and Nexon launcher before starting a new launch chain.")

    required = (
        "wine_prefix", "proton_directory", "runtime_directory", "umu_runner",
        "executable", "game_directory", "game_id", "environment",
    )
    missing = [name for name in required if name not in config]
    if missing:
        raise ValueError(f"Incomplete game_launch profile: {', '.join(missing)}.")
    paths = {name: expand_user(config[name]) for name in required[:-2]}
    checks = {
        "proton_directory": "Proton directory",
        "runtime_directory": "UMU runtime directory",
        "umu_runner": "UMU runner",
        "executable": "Nexon launcher executable",
        "game_directory": "Game working directory",
    }
    for name, label in checks.items():
        if not paths[name].exists():
            raise FileNotFoundError(f"{label} is unavailable: {paths[name]}")
    if not paths["proton_directory"].is_dir() or not paths["runtime_directory"].is_dir():
        raise RuntimeError("Configured Proton and UMU runtime paths must be directories.")
    if not os.access(paths["umu_runner"], os.X_OK):
        raise RuntimeError(f"UMU runner is not executable: {paths['umu_runner']}")
    preload = Path(PRELOAD_LIBRARY)
    if not preload.is_file():
        raise FileNotFoundError(
            f"Native speedhack preload was not shipped: {preload}. Refusing an uninstrumented launch."
        )
    if not config["game_id"] or not isinstance(config["environment"], dict):
        raise ValueError("game_id must be nonempty and environment must be a mapping.")

    environment = os.environ.copy()
    environment.update({str(key): str(value) for key, value in config["environment"].items()})
    environment.update({
        "WINEPREFIX": str(paths["wine_prefix"]),
        "PROTONPATH": str(paths["proton_directory"]),
        "UMU_RUNTIME": str(paths["runtime_directory"]),
        "GAMEID": str(config["game_id"]),
        "LD_PRELOAD": str(preload),
    })
    command = [str(paths["umu_runner"]), str(paths["executable"])]
    log = tempfile.NamedTemporaryFile(prefix="position-gui-launch-", suffix=".log", delete=False)
    log_path = Path(log.name)
    try:
        process = subprocess.Popen(
            command, cwd=paths["game_directory"], env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception:
        log.close()
        log_path.unlink(missing_ok=True)
        raise
    log.close()
    return process, log_path
