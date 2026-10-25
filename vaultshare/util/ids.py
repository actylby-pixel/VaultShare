"""ID 与字节编码的严格解析。

协议里所有 ID 都是定长十六进制：package_id / grant_id 16 字节（32 hex），
request_id 32 字节（64 hex），key_id 16 字节（32 hex）。解析失败必须当场拒绝，
绝不能把未验证的字符串带进哈希、HPKE 上下文或文件路径。
"""

from __future__ import annotations

import os
import re

__all__ = [
    "PKG_ID_BYTES",
    "GRANT_ID_BYTES",
    "REQUEST_ID_BYTES",
    "KEY_ID_BYTES",
    "new_hex_id",
    "parse_hex_id",
    "is_hex_id",
    "safe_name",
]

PKG_ID_BYTES = 16
GRANT_ID_BYTES = 16
REQUEST_ID_BYTES = 32
KEY_ID_BYTES = 16

_HEX_RE = re.compile(r"^[0-9a-f]+$")


def new_hex_id(nbytes: int) -> str:
    return os.urandom(nbytes).hex()


def parse_hex_id(value: str, nbytes: int, label: str = "ID") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是十六进制字符串")
    if len(value) != nbytes * 2 or not _HEX_RE.match(value):
        raise ValueError(f"{label} 必须是 {nbytes * 2} 位小写十六进制")
    return bytes.fromhex(value)


def is_hex_id(value, nbytes: int) -> bool:
    try:
        parse_hex_id(value, nbytes)
    except ValueError:
        return False
    return True


def safe_name(value: str, nbytes: int, label: str = "ID") -> str:
    """校验并返回十六进制 ID，可直接用作目录名。"""
    parse_hex_id(value, nbytes, label)
    return value
