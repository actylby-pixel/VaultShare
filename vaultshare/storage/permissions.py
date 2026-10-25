"""文件权限收紧。

POSIX：目录 0700、文件 0600。Windows：``icacls /inheritance:r`` 后只授予
当前用户完全控制。**Windows 上“当前用户”的 ACL 仍允许同一用户运行的任何
进程读取**——进程隔离不是 TEE，这一点在 SECURITY.md 里明说。

收紧失败不能让程序静默继续：调用方会收到 False，并应写审计/打印告警。
"""

from __future__ import annotations

import os
import subprocess
import sys

__all__ = ["tighten", "tighten_or_warn"]


def _windows_user() -> str:
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    if domain and user:
        return f"{domain}\\{user}"
    return user


def tighten(path: str, directory: bool = False) -> bool:
    """收紧权限；成功返回 True。"""
    try:
        if os.name == "nt":
            user = _windows_user()
            if not user:
                return False
            grant = f"{user}:(OI)(CI)F" if directory else f"{user}:F"
            cmd = ["icacls", path, "/inheritance:r", "/grant:r", grant]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            return proc.returncode == 0
        os.chmod(path, 0o700 if directory else 0o600)
        return True
    except OSError:
        return False


def tighten_or_warn(path: str, directory: bool = False) -> bool:
    ok = tighten(path, directory)
    if not ok:
        print(
            f"警告：无法收紧权限（请手动检查）：{path}",
            file=sys.stderr,
        )
    return ok
