"""Argon2id（口令 → 密钥）与 HKDF-SHA256（K_pkg → 流密钥）。

Argon2id 参数采用固定档案，不接受来自磁盘文件的任意成本参数：否则一个被
改过的身份文件可以让受害机器跑一套攻击者选定的弱参数。
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.pwhash import argon2id

__all__ = [
    "SALT_LEN",
    "KDF_PROFILE",
    "derive_kek",
    "hkdf_sha256",
    "stream_key",
]

SALT_LEN = argon2id.SALTBYTES
# (opslimit, memlimit)。与桌面应用 argon2id-v3-default 一致。
KDF_PROFILE = (3, 256 * 1024 * 1024)


def derive_kek(password: str | bytes, salt: bytes) -> bytearray:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError(f"salt 必须是 {SALT_LEN} 字节")
    raw = argon2id.kdf(
        size=32,
        password=bytes(password),
        salt=bytes(salt),
        opslimit=KDF_PROFILE[0],
        memlimit=KDF_PROFILE[1],
    )
    return bytearray(raw)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(bytes(ikm))


def stream_key(k_pkg: bytes, package_id: bytes) -> bytearray:
    """``K_stream = HKDF-SHA256(K_pkg, salt=package_id, info="VaultShare/container/v1")``。"""
    raw = hkdf_sha256(k_pkg, package_id, b"VaultShare/container/v1", 32)
    return bytearray(raw)
