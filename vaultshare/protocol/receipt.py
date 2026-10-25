"""回执：只覆盖 ``envelope_core``，避免哈希循环依赖。

``envelope_sha256 = SHA256(canonical(envelope_core))``。回执绝不能把含自身的
完整信封纳入哈希——那是一个无法计算的定义。接收方先重算该摘要，再用
**KeyConfig 里发送方签过名的**代理签名公钥验证回执。
"""

from __future__ import annotations

from ..crypto.keys import DOMAIN_RECEIPT, Ed25519Keys, sign_object, verify_object
from ..errors import ValidationError
from ..util.canonical import canonical_bytes, sha256_hex
from ..version import PROTOCOL_VERSION, RECEIPT_FORMAT
from .signing import require_int, require_str

__all__ = ["envelope_sha256", "make_receipt", "verify_receipt", "RECEIPT_FIELDS"]

RECEIPT_FIELDS = {
    "format",
    "version",
    "issued_at",
    "envelope_sha256",
    "broker_signature",
}


def envelope_sha256(envelope_core: dict) -> str:
    return sha256_hex(canonical_bytes(envelope_core))


def make_receipt(envelope_core: dict, broker_signing_private: bytes, *, issued_at: int) -> dict:
    record = {
        "format": RECEIPT_FORMAT,
        "version": PROTOCOL_VERSION,
        "issued_at": int(issued_at),
        "envelope_sha256": envelope_sha256(envelope_core),
    }
    signed = sign_object(
        Ed25519Keys.from_private(broker_signing_private), DOMAIN_RECEIPT, record
    )
    record["broker_signature"] = signed["signature"]
    return record


def verify_receipt(
    envelope_core: dict,
    receipt: dict,
    broker_signing_public: bytes,
) -> None:
    if not isinstance(receipt, dict) or set(receipt.keys()) != RECEIPT_FIELDS:
        raise ValidationError("回执字段集合非法")
    if receipt.get("format") != RECEIPT_FORMAT or receipt.get("version") != PROTOCOL_VERSION:
        raise ValidationError("回执版本非法")
    require_int(receipt.get("issued_at"), "issued_at", 0)
    expected = require_str(receipt.get("envelope_sha256"), "envelope_sha256", max_len=64)
    actual = envelope_sha256(envelope_core)
    if expected != actual:
        raise ValidationError("回执覆盖的 envelope_core 摘要不匹配")
    # 回执的签名主体是除 broker_signature 外的字段。
    body = {
        "format": receipt["format"],
        "version": receipt["version"],
        "issued_at": receipt["issued_at"],
        "envelope_sha256": receipt["envelope_sha256"],
        "signature": receipt["broker_signature"],
    }
    if not verify_object(broker_signing_public, DOMAIN_RECEIPT, body):
        raise ValidationError("回执签名无效")
