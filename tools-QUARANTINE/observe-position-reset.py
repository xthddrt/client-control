"""Shared x86-64 ptrace helpers for the scoped research tools."""

import ctypes
import importlib.util
import math
import os
from pathlib import Path
import time


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("character_resolver", DIRECTORY / "locate-character.py")
character = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(character)


class Registers(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
            "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
            "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base",
            "ds", "es", "fs", "gs",
        )
    ]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.ptrace.restype = ctypes.c_long


def ptrace(pid, request, address=0, data=0):
    ctypes.set_errno(0)
    result = _libc.ptrace(
        ctypes.c_ulong(request), ctypes.c_int(pid),
        ctypes.c_void_p(address), ctypes.c_void_p(data),
    )
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, f"ptrace request {request:#x} for PID {pid}: {os.strerror(error)}")
    return result


def wait_stop(pid, timeout):
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Stop timeout must be finite and nonnegative.")
    deadline = time.monotonic() + timeout
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if waited == pid:
            if os.WIFSTOPPED(status):
                return status
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                reason = (
                    f"exit code {os.WEXITSTATUS(status)}" if os.WIFEXITED(status)
                    else f"signal {os.WTERMSIG(status)}"
                )
                raise RuntimeError(f"PID {pid} exited while waiting for a ptrace stop: {reason} (status {status:#x}).")
            raise RuntimeError(f"PID {pid} returned unexpected wait status {status:#x}.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for PID {pid} to stop.")
        time.sleep(min(0.001, remaining))
