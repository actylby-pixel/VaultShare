"""兑换请求：接收方 → 代理，Web 不可解。

外层 HTTP 只携带 ``{request_id, package_id, hpke_enc, ciphertext}``。代理解封后
必须校验内外 ``request_id`` / ``package_id`` 一致——否则一个请求可以被挂到
另一个包上重放。

``created_at`` 允许 ±600 秒时钟偏差；``request_id`` 是 256 bit 随机值，承担
幂等键与去重键的双重职责。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..crypto import hpke
from ..errors import ValidationError
from ..util.base32c import is_valid_code, normalize_code
from ..util.canonical import b64u_decode, b64u_encode, canonical_bytes, sha256_hex
from ..util.ids import PKG_ID_BYTES, REQUEST_ID_BYTES, is_hex_id, new_hex_id
from ..util.timeutil import now
from ..version import PROTOCOL_VERSION, REDEEM_FORMAT
from .signing import redeem_info, require_b64, require_int, require_str

__all__ = [
    "RedeemRequest",
    "build_redeem_request",
    "open_redeem_request",
    "recipient_pk_hash",
    "MAX_SKEW",
]

MAX_SKEW = 600
_INNER_FIELDS = {
    "format",
    "version",
    "request_id",
    "package_id",
    "recipient_public_key",
    "code",
    "created_at",
    "nonce",
}
_OUTER_FIELDS = {"request_id", "package_id", "hpke_enc", "ciphertext"}
MAX_INNER_BYTES = 4096


@dataclass(frozen=True)
class RedeemRequest:
    request_id: str
    package_id: str
    recipient_public_key: bytes
    code: str
    created_at: int
    nonce: bytes
    inner: dict
    outer: dict

    @property
    def recipient_pk_hash(self) -> str:
        return recipient_pk_hash(self.recipient_public_key)


def recipient_pk_hash(public_key: bytes) -> str:
    return sha256_hex(bytes(public_key))


def build_redeem_request(
    *,
    package_id: str,
    broker_hpke_public: bytes,
    code: str,
    recipient_public_key: bytes,
    request_id: str | None = None,
    created_at: int | None = None,
) -> tuple[dict, dict]:
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    if len(recipient_public_key) != 32:
        raise ValidationError("接收方公钥必须是 32 字节")
    normalized = normalize_code(code)
    if not is_valid_code(normalized):
        raise ValidationError("口令格式非法", code="invalid_code")
    request_id = request_id or new_hex_id(REQUEST_ID_BYTES)
    if not is_hex_id(request_id, REQUEST_ID_BYTES):
        raise ValidationError("request_id 格式非法")
    created_at = int(now() if created_at is None else created_at)

    inner = {
        "format": REDEEM_FORMAT,
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "package_id": package_id,
        "recipient_public_key": b64u_encode(recipient_public_key),
        "code": normalized,
        "created_at": created_at,
        "nonce": b64u_encode(os.urandom(16)),
    }
    plaintext = canonical_bytes(inner)
    if len(plaintext) > MAX_INNER_BYTES:
        raise ValidationError("兑换请求过大")
    wrapped = hpke.seal(
        broker_hpke_public, plaintext, redeem_info(bytes.fromhex(package_id))
    )
    enc, ct = hpke.split_wrap(wrapped)
    outer = {
        "request_id": request_id,
        "package_id": package_id,
        "hpke_enc": b64u_encode(enc),
        "ciphertext": b64u_encode(ct),
    }
    return outer, inner


def open_redeem_request(
    outer: dict, broker_hpke_private: bytes, *, current_time: int | None = None
) -> RedeemRequest:
    if not isinstance(outer, dict) or set(outer.keys()) != _OUTER_FIELDS:
        raise ValidationError("兑换请求外层字段非法", code="invalid_redeem")
    request_id = require_str(outer.get("request_id"), "request_id", max_len=64)
    package_id = require_str(outer.get("package_id"), "package_id", max_len=32)
    if not is_hex_id(request_id, REQUEST_ID_BYTES):
        raise ValidationError("request_id 格式非法", code="invalid_redeem")
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法", code="invalid_redeem")
    enc = require_b64(outer.get("hpke_enc"), "hpke_enc", 32)
    ct = require_b64(outer.get("ciphertext"), "ciphertext")
    if len(ct) < 16 or len(ct) > MAX_INNER_BYTES + 16:
        raise ValidationError("兑换请求密文长度非法", code="invalid_redeem")

    try:
        plaintext = hpke.open_sealed(
            broker_hpke_private,
            enc + ct,
            redeem_info(bytes.fromhex(package_id)),
        )
    except hpke.DecryptionFailed as exc:
        raise ValidationError("兑换请求解封失败", code="invalid_redeem") from exc
    if len(plaintext) > MAX_INNER_BYTES:
        raise ValidationError("兑换请求过大", code="invalid_redeem")
    try:
        inner = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("兑换请求内层不是合法 JSON", code="invalid_redeem") from exc
    if not isinstance(inner, dict) or set(inner.keys()) != _INNER_FIELDS:
        raise ValidationError("兑换请求内层字段非法", code="invalid_redeem")
    if inner.get("format") != REDEEM_FORMAT or inner.get("version") != PROTOCOL_VERSION:
        raise ValidationError("兑换请求版本非法", code="invalid_redeem")
    if inner.get("request_id") != request_id or inner.get("package_id") != package_id:
        raise ValidationError("兑换请求内外标识不一致", code="invalid_redeem")
    recipient = require_b64(
        inner.get("recipient_public_key"), "recipient_public_key", 32
    )
    code = require_str(inner.get("code"), "code", max_len=64)
    if not is_valid_code(code) or normalize_code(code) != code:
        raise ValidationError("兑换口令未规范化或格式非法", code="invalid_code")
    created_at = require_int(inner.get("created_at"), "created_at", 0)
    current = int(now() if current_time is None else current_time)
    if abs(current - created_at) > MAX_SKEW:
        raise ValidationError("兑换请求时间戳超出允许范围", code="invalid_redeem")
    nonce = require_b64(inner.get("nonce"), "nonce", 16)
    return RedeemRequest(
        request_id=request_id,
        package_id=package_id,
        recipient_public_key=recipient,
        code=code,
        created_at=created_at,
        nonce=nonce,
        inner=inner,
        outer=outer,
    )
