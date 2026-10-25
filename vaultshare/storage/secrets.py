"""本地密钥文件。

* ``state_mac.key``：状态信封 HMAC（Web 与代理都读）；
* ``ipc_hmac.key``：本地 IPC 消息认证（Web 与代理都读）；
* ``code_mac.key``：口令 HMAC —— **只有代理读**；
* ``flask_secret.key``：会话签名。

生成用 ``O_CREAT|O_EXCL``，避免两个进程同时初始化时其中一方覆盖已存在的
密钥。文件权限由 ``permissions.tighten`` 收紧。
"""

from __future__ import annotations

import os

from ..config import Settings
from . import permissions

__all__ = [
    "read_or_create_key",
    "init_secret_files",
    "read_state_mac_key",
    "read_ipc_key",
    "read_code_mac_key",
    "read_flask_secret",
]


def read_or_create_key(path: str, length: int = 32) -> bytes:
    # Windows 上必须显式 O_BINARY：否则 msvcrt 以文本模式打开，随机字节中的
    # 0x0A/0x1A 会被改写或截断，生成的密钥长度/内容与预期不符。
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != length:
            raise ValueError(
                f"密钥文件长度错误（期望 {length}，实得 {len(data)}）：{path}"
            )
        return data
    try:
        data = os.urandom(length)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    permissions.tighten(path)
    return data


def init_secret_files(settings: Settings) -> None:
    settings.ensure_dirs()
    for path in (
        settings.state_mac_path,
        settings.ipc_hmac_path,
        settings.code_mac_path,
        settings.flask_secret_path,
    ):
        read_or_create_key(path, 32)
    permissions.tighten(str(settings.secrets_dir), directory=True)
    permissions.tighten(str(settings.broker_keys_dir), directory=True)


def read_state_mac_key(settings: Settings) -> bytes:
    return read_or_create_key(str(settings.state_mac_path), 32)


def read_ipc_key(settings: Settings) -> bytes:
    return read_or_create_key(str(settings.ipc_hmac_path), 32)


def read_code_mac_key(settings: Settings) -> bytes:
    return read_or_create_key(str(settings.code_mac_path), 32)


def read_flask_secret(settings: Settings) -> bytes:
    return read_or_create_key(str(settings.flask_secret_path), 32)
