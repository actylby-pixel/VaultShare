"""发送方身份的本地存储。

两个文件（同前缀，例如 ``sender``）：

* ``sender.json``：自我签名的公开身份记录，可安全上传/分享；
* ``sender.key``：Ed25519 + X25519 私钥，用 Argon2id 派生密钥 + XChaCha20-Poly1305
  加密，OG 的“私钥文件 0600”只是权限层，不替代加密。

口令优先从 ``VAULTSHARE_IDENTITY_PASSWORD`` 读取（便于自动化），否则用
``getpass`` 交互输入。KDF 参数固定为库内档案，不接受文件里自定义的成本参数。
"""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass

from ..crypto.aead import aead_decrypt, aead_encrypt
from ..crypto.kdf import derive_kek
from ..crypto.keys import x25519_generate, x25519_public_bytes
from ..crypto.memsec import wipe
from ..errors import ValidationError
from ..protocol.identity import SenderIdentity, build_sender_identity, verify_sender_identity
from ..storage import permissions
from ..storage.atomic import atomic_write_bytes
from ..util.canonical import b64u_decode, b64u_encode, canonical_bytes
from ..util.ids import KEY_ID_BYTES, new_hex_id
from ..util.timeutil import now
from ..version import PROTOCOL_VERSION

__all__ = [
    "SenderKeys",
    "create_identity",
    "save_identity",
    "load_identity",
    "password_from_env",
]

KEY_FILE_FORMAT = "vaultshare-identity-key"
_KEY_AAD = b"VaultShare/identity-key/v1"
_PASSWORD_ENV = "VAULTSHARE_IDENTITY_PASSWORD"


@dataclass(frozen=True)
class SenderKeys:
    identity: SenderIdentity
    ed25519_private: bytes
    x25519_private: bytes

    @property
    def x25519_public(self) -> bytes:
        return self.identity.x25519_public


def password_from_env() -> str | None:
    value = os.environ.get(_PASSWORD_ENV)
    return value if value else None


def _prompt_password(confirm: bool) -> str:
    password = getpass.getpass("身份私钥口令：")
    if not password:
        raise ValidationError("口令不能为空")
    if confirm and getpass.getpass("再次输入：") != password:
        raise ValidationError("两次输入的口令不一致")
    return password


def _encrypt_keys(ed_private: bytes, x_private: bytes, password: str) -> dict:
    salt = os.urandom(16)
    kek = derive_kek(password, salt)
    try:
        plaintext = canonical_bytes(
            {
                "version": PROTOCOL_VERSION,
                "ed25519_private": b64u_encode(ed_private),
                "x25519_private": b64u_encode(x_private),
            }
        )
        ciphertext, nonce = aead_encrypt(kek, plaintext, _KEY_AAD)
    finally:
        wipe(kek)
    return {
        "format": KEY_FILE_FORMAT,
        "version": PROTOCOL_VERSION,
        "kdf": "argon2id",
        "salt": b64u_encode(salt),
        "nonce": b64u_encode(nonce),
        "ciphertext": b64u_encode(ciphertext),
    }


def _decrypt_keys(record: dict, password: str) -> tuple[bytes, bytes]:
    if not isinstance(record, dict) or record.get("format") != KEY_FILE_FORMAT:
        raise ValidationError("身份私钥文件格式非法")
    if record.get("version") != PROTOCOL_VERSION or record.get("kdf") != "argon2id":
        raise ValidationError("不支持的身份私钥文件版本")
    try:
        salt = b64u_decode(record.get("salt"), expected_len=16)
        nonce = b64u_decode(record.get("nonce"), expected_len=24)
        ciphertext = b64u_decode(record.get("ciphertext"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("身份私钥文件编码非法") from exc
    kek = derive_kek(password, salt)
    try:
        plaintext = aead_decrypt(kek, ciphertext, nonce, _KEY_AAD)
    except Exception as exc:  # noqa: BLE001 - 统一为“口令错误或文件损坏”
        raise ValidationError("无法解密身份私钥：口令错误或文件已损坏") from exc
    finally:
        wipe(kek)
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("身份私钥内容非法") from exc
    try:
        return (
            b64u_decode(data["ed25519_private"], expected_len=32),
            b64u_decode(data["x25519_private"], expected_len=32),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("身份私钥字段非法") from exc


def create_identity(
    prefix: str,
    *,
    password: str | None = None,
    sender_key_id: str | None = None,
) -> SenderKeys:
    from ..crypto.keys import Ed25519Keys

    if not password:
        password = password_from_env() or _prompt_password(confirm=True)
    ed = Ed25519Keys.generate()
    x_private, x_public = x25519_generate()
    identity = build_sender_identity(
        ed.private_bytes,
        x_private,
        sender_key_id=sender_key_id or new_hex_id(KEY_ID_BYTES),
        created_at=now(),
    )
    keys = SenderKeys(identity, ed.private_bytes, x_private)
    if not x_public == identity.x25519_public:
        raise ValidationError("X25519 公钥绑定失败")
    save_identity(prefix, keys, password)
    return keys


def save_identity(prefix: str, keys: SenderKeys, password: str) -> None:
    public_path = f"{prefix}.json"
    key_path = f"{prefix}.key"
    public_bytes = canonical_bytes(keys.identity.record)
    private_record = _encrypt_keys(
        keys.ed25519_private, keys.x25519_private, password
    )
    atomic_write_bytes(public_path, public_bytes)
    atomic_write_bytes(key_path, canonical_bytes(private_record))
    permissions.tighten(public_path)
    permissions.tighten(key_path)


def load_identity(prefix: str, *, password: str | None = None) -> SenderKeys:
    public_path = f"{prefix}.json"
    key_path = f"{prefix}.key"
    try:
        with open(public_path, "rb") as f:
            identity = verify_sender_identity(json.loads(f.read().decode("utf-8")))
        with open(key_path, "rb") as f:
            record = json.loads(f.read().decode("utf-8"))
    except OSError as exc:
        raise ValidationError(f"身份文件不存在或不可读：{exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("身份文件不是合法 JSON") from exc

    if password is None:
        password = password_from_env() or _prompt_password(confirm=False)
    ed_private, x_private = _decrypt_keys(record, password)

    from ..crypto.keys import Ed25519Keys

    if Ed25519Keys.from_private(ed_private).public_bytes != identity.ed25519_public:
        raise ValidationError("Ed25519 私钥与公开身份记录不匹配")
    if x25519_public_bytes(x_private) != identity.x25519_public:
        raise ValidationError("X25519 私钥与公开身份记录不匹配")
    return SenderKeys(identity, ed_private, x_private)


def identity_fingerprint(keys: SenderKeys) -> str:
    """发送方身份摘要，接收方用它做 TOFU 固定。"""
    return keys.identity.digest
