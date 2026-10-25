"""规范化 JSON、哈希与 base64url 编码。

规范形式固定为 ``sort_keys=True, separators=(",", ":"), ensure_ascii=False``，
UTF-8 编码。所有签名、MAC、摘要都只对规范字节计算；解析后再编码必须得到同一
串字节，这是"服务器签名、客户端验证"能对上的前提。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

__all__ = [
    "canonical_bytes",
    "canonical_json",
    "sha256_bytes",
    "sha256_hex",
    "hmac_sha256",
    "hmac_verify",
    "b64u_encode",
    "b64u_decode",
    "const_eq",
]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_verify(key: bytes, data: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(key, data), expected)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def b64u_decode(value: str, *, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64url 值必须是字符串")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - 统一成 ValueError
        raise ValueError("非法的 base64url") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"base64url 解码后长度应为 {expected_len}，实得 {len(raw)}")
    return raw


def const_eq(a, b) -> bool:
    """常量时间比较；类型不同直接返回 False。"""
    if isinstance(a, str) and isinstance(b, str):
        return hmac.compare_digest(a, b)
    if isinstance(a, (bytes, bytearray)) and isinstance(b, (bytes, bytearray)):
        return hmac.compare_digest(bytes(a), bytes(b))
    return False


def fixed_domain(domain: bytes, *parts: bytes) -> bytes:
    """把域标签与若干字段编码成无歧义字节串。

    每个字段前加 4 字节大端长度。HPKE 的 ``info`` 与签名前缀都走这里；
    裸拼接会让 ``b"ab"+c`` 与 ``b"a"+bc`` 撞成同一串。
    """
    out = [len(domain).to_bytes(4, "big"), bytes(domain)]
    for part in parts:
        part = bytes(part)
        out.append(len(part).to_bytes(4, "big"))
        out.append(part)
    return b"".join(out)
