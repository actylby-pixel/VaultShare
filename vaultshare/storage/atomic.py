"""原子写入。

移植并简化自 ``vault_app/utils/atomic.py``：同目录临时文件 → 写满 → fsync →
原子替换 → 读回验证。Windows 用 ``MoveFileExW(REPLACE_EXISTING |
WRITE_THROUGH)``，瞬时占用有限重试。

保证：不会出现半个文件；替换后读回内容与写入一致。
不保证：突然断电时一定持久。目录项的 fsync 在 Windows 上不可用，只能尽力。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time

__all__ = [
    "ensure_dir",
    "fsync_dir",
    "replace_file",
    "atomic_write_bytes",
    "atomic_write_json",
    "read_json",
    "read_bytes",
    "cleanup_temp_files",
]

_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_TRANSIENT = frozenset({5, 32, 33})
_ATTEMPTS = 6


def ensure_dir(path) -> None:
    os.makedirs(os.fspath(path), exist_ok=True)


def fsync_dir(path) -> None:
    """尽力刷新目录项。Windows 打不开目录句柄，静默跳过。"""
    if os.name == "nt":
        return
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def replace_file(src: str, dst: str) -> None:
    if os.name != "nt":
        os.replace(src, dst)
        return

    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel32.MoveFileExW
    move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move.restype = ctypes.c_int

    last_error = 0
    for attempt in range(_ATTEMPTS):
        if move(src, dst, _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH):
            return
        if move(src, dst, _MOVEFILE_REPLACE_EXISTING):
            return
        last_error = ctypes.get_last_error()
        if last_error not in _TRANSIENT:
            break
        if attempt + 1 < _ATTEMPTS:
            time.sleep(0.01 * (attempt + 1))
    raise OSError(last_error, "原子替换失败", src, dst)


def atomic_write_bytes(path: str, data: bytes, keep_backup: bool = False) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(data))
            f.flush()
            os.fsync(f.fileno())
        if keep_backup and os.path.exists(path):
            replace_file(path, path + ".bak")
        replace_file(tmp, path)
        with open(path, "rb") as f:
            actual = f.read()
        if actual != bytes(data):
            raise OSError(f"原子替换后读回校验失败：{path}")
        fsync_dir(directory)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: str, obj, keep_backup: bool = False, indent: int = 2) -> None:
    payload = json.dumps(obj, ensure_ascii=False, indent=indent, sort_keys=True)
    atomic_write_bytes(path, payload.encode("utf-8"), keep_backup=keep_backup)


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def cleanup_temp_files(directory) -> int:
    """删除本目录遗留的 ``.<name>.*.tmp`` 半成品。返回删除数。"""
    count = 0
    directory = os.fspath(directory)
    if not os.path.isdir(directory):
        return 0
    for name in os.listdir(directory):
        if name.startswith(".") and name.endswith(".tmp"):
            try:
                os.remove(os.path.join(directory, name))
                count += 1
            except OSError:
                pass
    return count


def remove_tree(path) -> None:
    shutil.rmtree(os.fspath(path), ignore_errors=True)
