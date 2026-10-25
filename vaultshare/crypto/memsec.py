"""内存密钥清零与锁页（尽力而为）。

移植自 ``vault_app/crypto/memsec.py``。**诚实的边界**：Python 无法保证清除
解释器或密码库内部的全部副本；``bytes`` 不可原地清零；有调试权限的攻击者
可以转储进程内存。本模块只减少密钥在普通内存中的停留时间与换页风险。
"""

from __future__ import annotations

import ctypes
import os
from typing import Optional

_IS_WINDOWS = os.name == "nt"

_kernel32 = None
if _IS_WINDOWS:
    try:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover
        _kernel32 = None

_LOCK_FAILURES = 0


def lock_failure_count() -> int:
    return _LOCK_FAILURES


def _address_of(buf: bytearray) -> int:
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))


def virtual_lock(buf: bytearray) -> bool:
    global _LOCK_FAILURES
    if not isinstance(buf, bytearray):
        raise TypeError("virtual_lock() 只接受 bytearray")
    if not buf or _kernel32 is None:
        _LOCK_FAILURES += 1
        return False
    try:
        ok = bool(
            _kernel32.VirtualLock(
                ctypes.c_void_p(_address_of(buf)), ctypes.c_size_t(len(buf))
            )
        )
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        _LOCK_FAILURES += 1
    return ok


def virtual_unlock(buf: bytearray) -> None:
    if not isinstance(buf, bytearray) or not buf or _kernel32 is None:
        return
    try:
        _kernel32.VirtualUnlock(
            ctypes.c_void_p(_address_of(buf)), ctypes.c_size_t(len(buf))
        )
    except Exception:  # noqa: BLE001
        pass


def wipe(buf) -> None:
    if isinstance(buf, bytes):
        raise TypeError("bytes 不可变，无法原地清零；请使用 bytearray")
    if buf is None:
        return
    if not isinstance(buf, bytearray):
        raise TypeError(f"wipe() 只接受 bytearray，收到 {type(buf).__name__}")
    if not buf:
        return
    try:
        ctypes.memset(_address_of(buf), 0, len(buf))
    except Exception:  # noqa: BLE001
        for i in range(len(buf)):
            buf[i] = 0


def wipe_many(*bufs) -> None:
    for buf in bufs:
        if isinstance(buf, bytearray):
            wipe(buf)


class KeyGuard:
    __slots__ = ("buf", "locked")

    def __init__(self, buf: bytearray):
        if not isinstance(buf, bytearray):
            raise TypeError("KeyGuard 只接受 bytearray")
        self.buf = buf
        self.locked = virtual_lock(buf)

    def __enter__(self) -> bytearray:
        return self.buf

    def __exit__(self, exc_type, exc, tb) -> bool:
        wipe(self.buf)
        if self.locked:
            virtual_unlock(self.buf)
            self.locked = False
        return False
