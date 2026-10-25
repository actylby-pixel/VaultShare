"""XChaCha20-Poly1305 一次性认证加密。

移植自 ``vault_app/crypto/aead.py``（同一仓库），保持行为一致：24 字节随机
nonce、16 字节认证标签。用于加密身份私钥文件与代理本地缓存，不用于大文件。
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError

__all__ = ["aead_encrypt", "aead_decrypt", "CryptoError", "AEAD_ABYTES", "AEAD_KEY_BYTES"]

AEAD_ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES  # 16
AEAD_KEY_BYTES = 32
_NPUB_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24


def _check_key(key) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key 必须是 bytes/bytearray")
    if len(key) != AEAD_KEY_BYTES:
        raise ValueError(f"key 必须是 {AEAD_KEY_BYTES} 字节")
    return bytes(key)


def aead_encrypt(key, plaintext, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    nonce = os.urandom(_NPUB_LEN)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=bytes(plaintext), aad=aad, nonce=nonce, key=_check_key(key)
    )
    return ct, nonce


def aead_decrypt(key, ciphertext, nonce, aad: Optional[bytes] = None) -> bytes:
    if len(nonce) != _NPUB_LEN:
        raise ValueError(f"nonce 必须是 {_NPUB_LEN} 字节")
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext=bytes(ciphertext), aad=aad, nonce=bytes(nonce), key=_check_key(key)
    )
