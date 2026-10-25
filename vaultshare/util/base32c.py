"""Crockford Base32 口令的编码、归一化与分组显示。

26 个字符承载 130 bit 熵。服务端只保存 ``HMAC-SHA256(code_mac_key, 归一化口令)``，
明文口令在代理生成后立刻封给发送方 X25519 公钥，Web 进程与日志都看不到。
"""

from __future__ import annotations

import secrets

__all__ = [
    "ALPHABET",
    "CODE_CHARS",
    "generate_code",
    "normalize_code",
    "is_valid_code",
    "format_code",
]

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # 无 I L O U
CODE_CHARS = 26
_CODE_BITS = CODE_CHARS * 5  # 130
_GROUP = 5


def generate_code() -> str:
    """生成 26 字符规范口令（大写、无分隔符）。"""
    # 130 bit 不需要拒绝采样之外的补偿；取 136 bit 后截断会引入偏差，
    # 因此逐字符取 5 bit，拒绝落在 26..31 的取值。
    out: list[str] = []
    while len(out) < CODE_CHARS:
        value = secrets.randbits(8)
        idx = value & 0x1F
        # 32 个符号里只有前 26 个有效。取高 5 位同理，必须拒绝无效符号。
        if idx < len(ALPHABET):
            out.append(ALPHABET[idx])
    return "".join(out)


def normalize_code(value: str) -> str:
    """归一化：去分隔符/空白、转大写、``O→0``、``I/L→1``。"""
    if not isinstance(value, str):
        raise ValueError("口令必须是字符串")
    cleaned = []
    for ch in value:
        if ch.isalnum() is False and ch not in "-_ ":
            # 允许分隔符；其余标点一律视为非法，而不是悄悄忽略。
            raise ValueError("口令含有非法字符")
        if ch in "-_ ":
            continue
        ch = ch.upper()
        if ch == "O":
            ch = "0"
        elif ch in ("I", "L"):
            ch = "1"
        cleaned.append(ch)
    return "".join(cleaned)


def is_valid_code(value: str) -> bool:
    try:
        normalized = normalize_code(value)
    except ValueError:
        return False
    return len(normalized) == CODE_CHARS and all(c in ALPHABET for c in normalized)


def format_code(code: str) -> str:
    """显示形式 ``XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX``。"""
    normalized = normalize_code(code)
    if len(normalized) != CODE_CHARS:
        raise ValueError("口令长度不正确")
    return "-".join(
        normalized[i : i + _GROUP] for i in range(0, CODE_CHARS, _GROUP)
    )
