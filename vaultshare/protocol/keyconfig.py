"""KeyConfig：发送方把 ``K_pkg`` 封给代理，并绑定代理身份与策略摘要。

打包前发送方**必须**先取得并核对代理身份指纹；这里会重新计算指纹并与其
记录中的指纹比对。KeyConfig 由发送方 Ed25519 私钥签名，服务器与代理都必须
先验签、再验身份绑定。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import hpke
from ..crypto.keys import (
    DOMAIN_KEYCONFIG,
    broker_fingerprint,
    sign_object,
    verify_object,
)
from ..errors import ValidationError
from ..util.canonical import b64u_encode, sha256_hex
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..version import KEYCONFIG_FORMAT, PROTOCOL_VERSION
from .identity import BrokerIdentity, SenderIdentity, check_sender_binding
from .signing import keyconfig_info, require_b64, require_int, require_str
from ..crypto.memsec import wipe

__all__ = ["build_keyconfig", "verify_keyconfig", "open_package_key", "KeyConfigParsed", "keyconfig_digest"]

SUITE_NAME = hpke.SUITE_NAME


@dataclass(frozen=True)
class KeyConfigParsed:
    record: dict
    package_id: str
    package_id_bytes: bytes
    policy_hash: str
    broker_key_id: str
    broker_hpke_public: bytes
    broker_signing_public: bytes
    broker_fingerprint: str
    sender: SenderIdentity


def keyconfig_digest(record: dict) -> str:
    from ..util.canonical import canonical_bytes, sha256_bytes

    return sha256_bytes(canonical_bytes(record)).hex()


def build_keyconfig(
    package_id: str,
    policy_hash: str,
    k_pkg: bytes,
    broker: BrokerIdentity,
    sender: SenderIdentity,
    signer_private: bytes,
    *,
    created_at: int,
) -> dict:
    from ..crypto.keys import Ed25519Keys

    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    if not is_hex_id(policy_hash, 32):
        raise ValidationError("policy_hash 必须是 64 位十六进制")
    if len(k_pkg) != 32:
        raise ValidationError("K_pkg 必须是 32 字节")
    package_bytes = bytes.fromhex(package_id)
    info = keyconfig_info(package_bytes, bytes.fromhex(policy_hash))
    wrapped = hpke.seal(broker.hpke_public, k_pkg, info)
    enc, ct = hpke.split_wrap(wrapped)
    record = {
        "format": KEYCONFIG_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "suite": SUITE_NAME,
        "broker": {
            "key_id": broker.key_id,
            "hpke_public_key": b64u_encode(broker.hpke_public),
            "signing_public_key": b64u_encode(broker.signing_public),
            "fingerprint": broker.fingerprint,
        },
        "hpke_wrap": {"enc": b64u_encode(enc), "ciphertext": b64u_encode(ct)},
        "policy_hash": policy_hash,
        "sender_key_id": sender.sender_key_id,
        "sender_identity_hash": sender.digest,
        "sender_public_key": b64u_encode(sender.ed25519_public),
        "created_at": int(created_at),
    }
    return sign_object(Ed25519Keys.from_private(signer_private), DOMAIN_KEYCONFIG, record)


_ALLOWED = {
    "format",
    "version",
    "package_id",
    "suite",
    "broker",
    "hpke_wrap",
    "policy_hash",
    "sender_key_id",
    "sender_identity_hash",
    "sender_public_key",
    "created_at",
    "signature",
}


def verify_keyconfig(record: dict, identity: SenderIdentity | None = None) -> KeyConfigParsed:
    if not isinstance(record, dict):
        raise ValidationError("KeyConfig 必须是 JSON 对象")
    if record.get("format") != KEYCONFIG_FORMAT:
        raise ValidationError("KeyConfig 格式标识不匹配")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的 KeyConfig 版本")
    if set(record.keys()) != _ALLOWED:
        raise ValidationError("KeyConfig 字段集合非法")
    package_id = require_str(record.get("package_id"), "package_id", max_len=32)
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("KeyConfig 的 package_id 格式非法")
    if record.get("suite") != SUITE_NAME:
        raise ValidationError("不支持的 HPKE 套件")
    policy_hash = require_str(record.get("policy_hash"), "policy_hash", max_len=64)
    if not is_hex_id(policy_hash, 32):
        raise ValidationError("policy_hash 格式非法")

    broker = record.get("broker")
    if not isinstance(broker, dict) or set(broker.keys()) != {
        "key_id",
        "hpke_public_key",
        "signing_public_key",
        "fingerprint",
    }:
        raise ValidationError("KeyConfig.broker 结构非法")
    key_id = require_str(broker.get("key_id"), "broker.key_id", max_len=64)
    if not is_hex_id(key_id, 16):
        raise ValidationError("broker.key_id 格式非法")
    hpke_pub = require_b64(broker.get("hpke_public_key"), "broker.hpke_public_key", 32)
    sign_pub = require_b64(broker.get("signing_public_key"), "broker.signing_public_key", 32)
    fp = require_str(broker.get("fingerprint"), "broker.fingerprint", max_len=64)
    computed = broker_fingerprint(
        key_id, broker["hpke_public_key"], broker["signing_public_key"]
    )
    if computed != fp:
        raise ValidationError("KeyConfig 中代理指纹与公钥不匹配")

    wrap = record.get("hpke_wrap")
    if not isinstance(wrap, dict) or set(wrap.keys()) != {"enc", "ciphertext"}:
        raise ValidationError("KeyConfig.hpke_wrap 结构非法")
    enc = require_b64(wrap.get("enc"), "hpke_wrap.enc", 32)
    ct = require_b64(wrap.get("ciphertext"), "hpke_wrap.ciphertext")
    if len(ct) != 48:  # 32 字节 K_pkg + 16 字节 tag
        raise ValidationError("KeyConfig.hpke_wrap.ciphertext 长度非法")

    sender_pub = require_b64(record.get("sender_public_key"), "sender_public_key", 32)
    if not verify_object(sender_pub, DOMAIN_KEYCONFIG, record):
        raise ValidationError("KeyConfig 签名无效")

    sender_key_id = require_str(record.get("sender_key_id"), "sender_key_id", max_len=64)
    sender_identity_digest = require_str(
        record.get("sender_identity_hash"), "sender_identity_hash", max_len=64
    )
    if identity is not None:
        check_sender_binding(record, identity)
    # identity=None 时只完成签名与结构验证；调用方必须把三个发送方字段与
    # 已注册身份逐项比对（``check_sender_fields``）。
    require_int(record.get("created_at"), "created_at", minimum=0)
    return KeyConfigParsed(
        record=record,
        package_id=package_id,
        package_id_bytes=bytes.fromhex(package_id),
        policy_hash=policy_hash,
        broker_key_id=key_id,
        broker_hpke_public=hpke_pub,
        broker_signing_public=sign_pub,
        broker_fingerprint=computed,
        sender=identity,  # type: ignore[arg-type]
    )


def open_package_key(parsed: KeyConfigParsed, broker_hpke_private: bytes) -> bytearray:
    """代理侧解封 ``K_pkg``。调用方负责核对 key_id 与当前密钥。"""
    wrap = parsed.record["hpke_wrap"]
    enc = require_b64(wrap["enc"], "hpke_wrap.enc", 32)
    ct = require_b64(wrap["ciphertext"], "hpke_wrap.ciphertext")
    info = keyconfig_info(parsed.package_id_bytes, bytes.fromhex(parsed.policy_hash))
    try:
        raw = hpke.open_sealed(broker_hpke_private, enc + ct, info)
    except hpke.DecryptionFailed as exc:
        raise ValidationError("KeyConfig 解封失败（代理密钥或上下文不匹配）") from exc
    if len(raw) != 32:
        raise ValidationError("解封得到的 K_pkg 长度非法")
    return bytearray(raw)
