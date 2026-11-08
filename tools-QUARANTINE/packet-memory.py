"""Shared process-memory writes and ptrace trap ownership for packet tools."""

import ctypes
import importlib.util
import os
from pathlib import Path
import signal


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("reset_observer", DIRECTORY / "observe-position-reset.py")
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)
character = observer.character


class Iov(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


libc = ctypes.CDLL(None, use_errno=True)
libc.process_vm_writev.restype = ctypes.c_ssize_t


def write_memory(pid, address, data):
    data = bytes(data)
    buffer = ctypes.create_string_buffer(data, len(data))
    local = Iov(ctypes.cast(buffer, ctypes.c_void_p), len(data))
    remote = Iov(address, len(data))
    if libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) != len(data):
        raise OSError(ctypes.get_errno(), "process_vm_writev failed")


def owns_trap(pid, registers, targets):
    slot = targets.get(registers.rip)
    return slot is not None and bool(observer.ptrace(pid, 3, 848 + 6 * 8) & (1 << slot))


def pending_signal(pid, state, targets=None):
    if state >> 16:
        return 0
    number = os.WSTOPSIG(state)
    if number == signal.SIGTRAP and targets is not None:
        registers = observer.Registers()
        observer.ptrace(pid, 12, 0, ctypes.addressof(registers))
        if owns_trap(pid, registers, targets):
            return 0
    return number
