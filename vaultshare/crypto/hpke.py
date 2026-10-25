"""HPKE 固定套件封装：DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM。

**实现事实（必须与文档一致）**：``cryptography`` 50.0.2 的
``hpke.Suite.encrypt/decrypt`` 只提供 ``info``，不暴露 RFC 9180 的 ``aad``
参数。因此本协议把所有上下文绑定字节编码进 ``info``（见
``util.canonical.fixed_domain``），而不是 RFC 9180 意义上的 AAD。

这仍然提供完整认证：``info`` 进入 HPKE 的 key schedule，任何改动都会导致
解封失败。但它与 RFC 9180 附录 A 的测试向量（那些向量固定了非空 AAD）不是
逐字节兼容的。详见 ``docs/PROTOCOL.md`` 的“与 RFC 9180 的偏差”。

线格式：``enc(32) || ciphertext``。JSON 中拆成 ``enc`` 与 ``ciphertext`` 两个
base64url 字段；二进制容器中直接拼接。
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..errors import ValidationError

__all__ = [
    "SUITE_NAME",
    "ENC_LEN",
    "TAG_LEN",
    "generate_keypair",
    "public_from_private",
    "seal",
    "open_sealed",
    "split_wrap",
    "join_wrap",
]

SUITE_NAME = "HPKE-X25519-HKDF-SHA256-AES128GCM"
ENC_LEN = 32
TAG_LEN = 16

_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)


def generate_keypair() -> tuple[bytes, bytes]:
    """返回 ``(private_bytes, public_bytes)``，各 32 字节。"""
    private = X25519PrivateKey.generate()
    priv_raw = private.private_bytes_raw()
    pub_raw = private.public_key().public_bytes_raw()
    return priv_raw, pub_raw


def public_from_private(private_bytes: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(bytes(private_bytes)).public_key().public_bytes_raw()


def seal(recipient_public: bytes, plaintext: bytes, info: bytes) -> bytes:
    """单次封包，返回 ``enc || ciphertext``。"""
    if len(recipient_public) != 32:
        raise ValidationError("X25519 公钥必须是 32 字节")
    try:
        public_key = X25519PublicKey.from_public_bytes(bytes(recipient_public))
    except ValueError as exc:
        raise ValidationError("非法的 X25519 公钥") from exc
    return _SUITE.encrypt(bytes(plaintext), public_key, info=bytes(info))


def open_sealed(recipient_private: bytes, wrapped: bytes, info: bytes) -> bytes:
    """解封 ``enc || ciphertext``；认证失败抛 ``DecryptionFailed``。"""
    if len(recipient_private) != 32:
        raise ValidationError("X25519 私钥必须是 32 字节")
    if len(wrapped) < ENC_LEN + TAG_LEN:
        raise DecryptionFailed("HPKE 密文过短")
    private_key = X25519PrivateKey.from_private_bytes(bytes(recipient_private))
    try:
        return _SUITE.decrypt(bytes(wrapped), private_key, info=bytes(info))
    except InvalidTag as exc:
        raise DecryptionFailed("HPKE 解封失败（密钥或上下文不匹配）") from exc


class DecryptionFailed(Exception):
    """HPKE 认证失败。调用方映射成拒绝，不泄露具体原因。"""


def split_wrap(wrapped: bytes) -> tuple[bytes, bytes]:
    if len(wrapped) < ENC_LEN + TAG_LEN:
        raise ValidationError("HPKE 封装过短")
    return wrapped[:ENC_LEN], wrapped[ENC_LEN:]


def join_wrap(enc: bytes, ciphertext: bytes) -> bytes:
    if len(enc) != ENC_LEN:
        raise ValidationError("HPKE enc 必须是 32 字节")
    return bytes(enc) + bytes(ciphertext)
