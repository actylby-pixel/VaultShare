"""Ed25519 / X25519 密钥生成、签名与身份指纹。

签名域分离：``sign(domain || SHA256(canonical(body_without_signature)))``。
调用方必须为每类对象传不同的 ``domain``，这样一条签名不能在 KeyConfig、
Policy、身份记录或回执之间搬运。
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..util.canonical import (
    b64u_decode,
    b64u_encode,
    canonical_bytes,
    sha256_bytes,
    sha256_hex,
)

__all__ = [
    "Ed25519Keys",
    "generate_ed25519",
    "sign_object",
    "verify_object",
    "signature_message",
    "ed25519_public_bytes",
    "x25519_generate",
    "x25519_public_bytes",
    "broker_fingerprint",
    "identity_hash",
]

DOMAIN_KEYCONFIG = b"VaultShare/sig/keyconfig/v1"
DOMAIN_POLICY = b"VaultShare/sig/policy/v1"
DOMAIN_SENDER_IDENTITY = b"VaultShare/sig/sender-identity/v1"
DOMAIN_RECEIPT = b"VaultShare/sig/receipt/v1"
DOMAIN_AUTHORIZATION = b"VaultShare/sig/authorization/v1"
DOMAIN_GRANT_BATCH = b"VaultShare/sig/grant-batch/v1"
DOMAIN_UPLOAD_KEY = b"VaultShare/sig/upload-key/v1"


class Ed25519Keys:
    __slots__ = ("private_bytes", "public_bytes")

    def __init__(self, private_bytes: bytes, public_bytes: bytes):
        if len(private_bytes) != 32 or len(public_bytes) != 32:
            raise ValueError("Ed25519 密钥必须是 32 字节")
        self.private_bytes = bytes(private_bytes)
        self.public_bytes = bytes(public_bytes)

    @classmethod
    def generate(cls) -> "Ed25519Keys":
        private = Ed25519PrivateKey.generate()
        return cls(
            private.private_bytes_raw(),
            private.public_key().public_bytes_raw(),
        )

    @classmethod
    def from_private(cls, private_bytes: bytes) -> "Ed25519Keys":
        private = Ed25519PrivateKey.from_private_bytes(bytes(private_bytes))
        return cls(private_bytes, private.public_key().public_bytes_raw())

    def sign(self, message: bytes) -> bytes:
        private = Ed25519PrivateKey.from_private_bytes(self.private_bytes)
        return private.sign(bytes(message))


def generate_ed25519() -> Ed25519Keys:
    return Ed25519Keys.generate()


def ed25519_public_bytes(private_bytes: bytes) -> bytes:
    return Ed25519Keys.from_private(private_bytes).public_bytes


def x25519_generate() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def x25519_public_bytes(private_bytes: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(bytes(private_bytes))
        .public_key()
        .public_bytes_raw()
    )


def signature_message(domain: bytes, obj: dict) -> bytes:
    """域标签 ‖ SHA256(canonical(除 signature 外的对象))。"""
    body = {k: v for k, v in obj.items() if k != "signature"}
    return bytes(domain) + sha256_bytes(canonical_bytes(body))


def sign_object(keys: Ed25519Keys, domain: bytes, obj: dict) -> dict:
    """签名并返回**可 JSON 序列化**的对象：signature 为 base64url 字符串。

    线上与磁盘格式统一使用字符串；内存中的 bytes 只在签名计算前短暂存在。
    """
    signed = dict(obj)
    signed.pop("signature", None)
    signed["signature"] = b64u_encode(keys.sign(signature_message(domain, signed)))
    return signed


def verify_object(public_bytes: bytes, domain: bytes, obj: dict) -> bool:
    signature = obj.get("signature")
    try:
        if isinstance(signature, str):
            raw = b64u_decode(signature, expected_len=64)
        elif isinstance(signature, (bytes, bytearray)):
            raw = bytes(signature)
        else:
            return False
        if len(raw) != 64:
            return False
        key = Ed25519PublicKey.from_public_bytes(bytes(public_bytes))
        key.verify(raw, signature_message(domain, obj))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def broker_fingerprint(key_id: str, hpke_public_key: str, signing_public_key: str) -> str:
    """``SHA256(canonical({"key_id","hpke_public_key","signing_public_key"}))``。"""
    return sha256_hex(
        canonical_bytes(
            {
                "key_id": key_id,
                "hpke_public_key": hpke_public_key,
                "signing_public_key": signing_public_key,
            }
        )
    )


def identity_hash(record: dict) -> str:
    """发送方身份摘要：对除 signature 外的规范化内容取 SHA256。"""
    body = {k: v for k, v in record.items() if k != "signature"}
    return sha256_hex(canonical_bytes(body))


def write_private_key(path: str, data: bytes) -> None:
    """创建/覆盖 0600 私钥文件（同目录原子替换）。

    Windows 上 0600 不会映射成 ACL；调用方还应调用
    ``storage.permissions.restrict_file`` 收紧权限。
    """
    import tempfile

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".key.", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(data))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def read_private_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
