"""发送方身份记录与代理身份指纹。

发送方身份把 Ed25519（签名）与 X25519（接收口令密文）**绑定在同一条自我签名
记录**里。KeyConfig 与 Policy 都必须引用同一个 ``sender_key_id`` 与
``sender_identity_hash``；否则服务器可以拿 A 的签名公钥去验证 B 的 X25519
公钥，把口令密文交给错误的接收方。

代理身份指纹是发送方的信任锚：
``SHA256(canonical({key_id, hpke_public_key, signing_public_key}))``。
指纹必须通过**可信渠道**核对，不能只信服务器返回的内容。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import hpke
from ..crypto.keys import (
    DOMAIN_SENDER_IDENTITY,
    broker_fingerprint,
    identity_hash,
    signature_message,
    verify_object,
)
from ..errors import ValidationError
from ..util.canonical import b64u_encode
from ..util.ids import KEY_ID_BYTES, is_hex_id, new_hex_id
from ..version import BROKER_IDENTITY_FORMAT, IDENTITY_FORMAT, PROTOCOL_VERSION
from .signing import require_b64, require_int, require_str

__all__ = [
    "SenderIdentity",
    "BrokerIdentity",
    "build_sender_identity",
    "verify_sender_identity",
    "build_broker_identity",
    "verify_broker_identity",
    "identity_hash",
    "broker_fingerprint",
]


@dataclass(frozen=True)
class SenderIdentity:
    record: dict
    sender_key_id: str
    ed25519_public: bytes
    x25519_public: bytes
    digest: str


@dataclass(frozen=True)
class BrokerIdentity:
    key_id: str
    hpke_public: bytes
    signing_public: bytes
    fingerprint: str
    record: dict


def build_sender_identity(
    ed25519_private: bytes,
    x25519_private: bytes,
    *,
    sender_key_id: str | None = None,
    created_at: int,
) -> SenderIdentity:
    from ..crypto.keys import Ed25519Keys, x25519_public_bytes

    keys = Ed25519Keys.from_private(ed25519_private)
    key_id = sender_key_id or new_hex_id(KEY_ID_BYTES)
    record = {
        "format": IDENTITY_FORMAT,
        "version": PROTOCOL_VERSION,
        "sender_key_id": key_id,
        "ed25519_public_key": b64u_encode(keys.public_bytes),
        "x25519_public_key": b64u_encode(x25519_public_bytes(x25519_private)),
        "created_at": int(created_at),
    }
    signed = sign_sender_identity(keys, record)
    return verify_sender_identity(signed)


def sign_sender_identity(keys, record: dict) -> dict:
    from ..crypto.keys import sign_object

    return sign_object(keys, DOMAIN_SENDER_IDENTITY, record)


def verify_sender_identity(record: dict) -> SenderIdentity:
    if not isinstance(record, dict):
        raise ValidationError("身份记录必须是 JSON 对象")
    if record.get("format") != IDENTITY_FORMAT:
        raise ValidationError("身份记录格式标识不匹配")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的身份记录版本")
    key_id = require_str(record.get("sender_key_id"), "sender_key_id", max_len=64)
    if not is_hex_id(key_id, KEY_ID_BYTES):
        raise ValidationError("sender_key_id 格式非法")
    ed_pub = require_b64(record.get("ed25519_public_key"), "ed25519_public_key", 32)
    x_pub = require_b64(record.get("x25519_public_key"), "x25519_public_key", 32)
    require_int(record.get("created_at"), "created_at", minimum=0)
    # 只允许已知字段，防止把额外字段塞进签名却无人校验。
    allowed = {
        "format",
        "version",
        "sender_key_id",
        "ed25519_public_key",
        "x25519_public_key",
        "created_at",
        "signature",
    }
    if set(record.keys()) != allowed:
        raise ValidationError("身份记录字段集合非法")
    if not verify_object(ed_pub, DOMAIN_SENDER_IDENTITY, record):
        raise ValidationError("身份记录签名无效")
    digest = identity_hash(record)
    return SenderIdentity(record, key_id, ed_pub, x_pub, digest)


def build_broker_identity(
    key_id: str, hpke_public: bytes, signing_public: bytes, *, created_at: int
) -> BrokerIdentity:
    hpke_b64 = b64u_encode(hpke_public)
    sign_b64 = b64u_encode(signing_public)
    fp = broker_fingerprint(key_id, hpke_b64, sign_b64)
    record = {
        "format": BROKER_IDENTITY_FORMAT,
        "version": PROTOCOL_VERSION,
        "key_id": key_id,
        "hpke_public_key": hpke_b64,
        "signing_public_key": sign_b64,
        "fingerprint": fp,
        "created_at": int(created_at),
    }
    return BrokerIdentity(key_id, bytes(hpke_public), bytes(signing_public), fp, record)


def verify_broker_identity(record: dict, expected_fingerprint: str | None = None) -> BrokerIdentity:
    if not isinstance(record, dict):
        raise ValidationError("代理身份必须是 JSON 对象")
    if record.get("format") != BROKER_IDENTITY_FORMAT:
        raise ValidationError("代理身份格式标识不匹配")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的代理身份版本")
    key_id = require_str(record.get("key_id"), "key_id", max_len=64)
    if not is_hex_id(key_id, KEY_ID_BYTES):
        raise ValidationError("代理 key_id 格式非法")
    hpke_pub = require_b64(record.get("hpke_public_key"), "hpke_public_key", 32)
    sign_pub = require_b64(record.get("signing_public_key"), "signing_public_key", 32)
    fp = require_str(record.get("fingerprint"), "fingerprint", max_len=64)
    computed = broker_fingerprint(key_id, record["hpke_public_key"], record["signing_public_key"])
    if computed != fp:
        raise ValidationError("代理身份指纹与公钥不匹配")
    if expected_fingerprint is not None and computed != expected_fingerprint.lower():
        raise ValidationError("代理身份指纹与可信指纹不匹配")
    # 代理身份记录不是由代理私钥签名的（发送方在打包时尚未信任它）；
    # 它的真实性来自带外核对的指纹。这里只做结构性校验。
    return BrokerIdentity(key_id, hpke_pub, sign_pub, computed, dict(record))


def check_sender_binding(keyconfig: dict, identity: SenderIdentity) -> None:
    if keyconfig.get("sender_key_id") != identity.sender_key_id:
        raise ValidationError("KeyConfig 的 sender_key_id 与身份记录不一致")
    if keyconfig.get("sender_identity_hash") != identity.digest:
        raise ValidationError("KeyConfig 的发送方身份摘要不一致")
    if keyconfig.get("sender_public_key") != b64u_encode(identity.ed25519_public):
        raise ValidationError("KeyConfig 的发送方签名公钥不一致")


def check_policy_binding(policy: dict, identity: SenderIdentity) -> None:
    if policy.get("sender_key_id") != identity.sender_key_id:
        raise ValidationError("Policy 的 sender_key_id 与身份记录不一致")
    if policy.get("sender_identity_hash") != identity.digest:
        raise ValidationError("Policy 的发送方身份摘要不一致")
    if policy.get("sender_public_key") != b64u_encode(identity.ed25519_public):
        raise ValidationError("Policy 的发送方签名公钥不一致")


def check_sender_fields(record: dict, entry: dict, label: str) -> None:
    """用已注册身份（状态文件里的精简记录）核对某个签名对象的发送方字段。"""
    if not isinstance(entry, dict) or entry.get("revoked"):
        raise ValidationError(f"{label} 的发送方身份未注册或已撤销")
    if record.get("sender_key_id") != entry.get("sender_key_id"):
        raise ValidationError(f"{label} 的发送方 key_id 不一致")
    if record.get("sender_identity_hash") != entry.get("identity_hash"):
        raise ValidationError(f"{label} 的发送方身份摘要不一致")
    if record.get("sender_public_key") != entry.get("ed25519_public_key"):
        raise ValidationError(f"{label} 的发送方 Ed25519 公钥不一致")


def check_registered(body: dict, identity: SenderIdentity) -> dict:
    entry = body.get("senders", {}).get(identity.sender_key_id)
    if not isinstance(entry, dict):
        raise ValidationError("发送方身份未注册")
    if entry.get("revoked"):
        raise ValidationError("发送方身份已撤销")
    if entry.get("identity_hash") != identity.digest:
        raise ValidationError("发送方身份摘要与注册记录不一致")
    if entry.get("ed25519_public_key") != identity.record["ed25519_public_key"]:
        raise ValidationError("发送方 Ed25519 公钥与注册记录不一致")
    if entry.get("x25519_public_key") != identity.record["x25519_public_key"]:
        raise ValidationError("发送方 X25519 公钥与注册记录不一致")
    return entry


def build_sealer_info(package_id: bytes, grant_id: bytes, sender_x25519_pub: bytes) -> bytes:
    from .signing import code_info

    return code_info(package_id, grant_id, sender_x25519_pub)


def seal_code(
    code: str,
    package_id: bytes,
    grant_id: bytes,
    sender_x25519_public: bytes,
) -> dict:
    """代理生成口令后立即封给发送方。返回 JSON 字段。"""
    info = build_sealer_info(package_id, grant_id, sender_x25519_public)
    wrapped = hpke.seal(sender_x25519_public, code.encode("ascii"), info)
    enc, ct = hpke.split_wrap(wrapped)
    return {"enc": b64u_encode(enc), "ciphertext": b64u_encode(ct)}
