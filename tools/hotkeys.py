"""Passive Linux evdev hotkeys for the Qt research GUI."""

import fcntl
import os
from pathlib import Path
import select
import struct
import threading

from PySide6.QtCore import QThread, Signal


KEY_CODES = {
    "pause": 119,
    "home": 102,
    "scrolllock": 70,
    "insert": 110,
    "end": 107,
}
MODIFIER_CODES = {
    "ctrl": (29, 97),
    "shift": (42, 54),
    "alt": (56, 100),
    "meta": (125, 126),
}
MODIFIER_LABELS = {"ctrl": "Ctrl", "shift": "Shift", "alt": "Alt", "meta": "Super"}
KEY_LABELS = {
    "pause": "Pause", "home": "Home", "scrolllock": "Scroll Lock",
    "insert": "Insert", "end": "End",
}


def key_label(key):
    return KEY_LABELS.get(key, key.replace("_", " ").title())


def _device_bits(fd, kind, size=96):
    request = (2 << 30) | (size << 16) | (ord("E") << 8) | (0x20 + kind)
    buffer = bytearray(size)
    fcntl.ioctl(fd, request, buffer)
    return buffer


def _has_bit(data, bit):
    return bool(data[bit // 8] & (1 << (bit % 8)))


def input_devices(required_codes):
    devices = []
    for path in sorted(Path("/dev/input").glob("event*")):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            continue
        try:
            events = _device_bits(fd, 0)
            keys = _device_bits(fd, 1)
            if _has_bit(events, 1) and all(_has_bit(keys, code) for code in required_codes):
                devices.append((path, fd))
            else:
                os.close(fd)
        except OSError:
            os.close(fd)
    return devices


class HotkeyListener(QThread):
    activated = Signal(str)
    status = Signal(str)

    def __init__(self, bindings, modifiers, parent=None):
        super().__init__(parent)
        self.bindings = dict(bindings)
        self.modifier_codes = {
            code for name in modifiers for code in MODIFIER_CODES.get(name, ())
        }
        if len(self.modifier_codes) != sum(len(MODIFIER_CODES.get(name, ())) for name in modifiers):
            raise ValueError("Unknown hotkey modifier.")
        self._stop = threading.Event()

    def run(self):
        required = set(self.bindings.values()) | self.modifier_codes
        devices = input_devices(required)
        if not devices:
            self.status.emit(
                "Global hotkeys: unavailable (no readable evdev keyboard with every binding)"
            )
            return
        pressed = set()
        actions = {code: action for action, code in self.bindings.items()}
        self.status.emit(f"Global hotkeys: listening on {len(devices)} evdev device(s)")
        try:
            while not self._stop.is_set():
                fds = [fd for _, fd in devices]
                if not fds:
                    self.status.emit("Global hotkeys: unavailable (all evdev devices disconnected)")
                    return
                readable, _, _ = select.select(fds, [], [], 0.25)
                for fd in readable:
                    try:
                        data = os.read(fd, 24 * 32)
                    except BlockingIOError:
                        continue
                    except OSError:
                        devices = [(path, other) for path, other in devices if other != fd]
                        os.close(fd)
                        continue
                    for offset in range(0, len(data) - len(data) % 24, 24):
                        _, _, event_type, code, value = struct.unpack_from("qqHHI", data, offset)
                        if event_type != 1 or value not in (0, 1):
                            continue
                        was_pressed = code in pressed
                        if value:
                            pressed.add(code)
                        else:
                            pressed.discard(code)
                        if (
                            value and not was_pressed and code in actions
                            and self.modifier_codes <= pressed
                        ):
                            self.activated.emit(actions[code])
        finally:
            for _, fd in devices:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self.status.emit("Global hotkeys: stopped")

    def stop(self):
        self._stop.set()
