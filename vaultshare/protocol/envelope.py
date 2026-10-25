"""密钥信封：代理把 ``K_pkg`` 重新封给接收方，并附上回执。

绑定字段全部进入 HPKE ``info``：``package_id``、``grant_id``、``request_id``、
``sha256(recipient_pk)``、``config_version``。代理密钥 ``key_id`` 与
``recipient_pk_hash`` 同时出现在明文核心字段里，便于接收方核对。

接收方校验顺序（``open_envelope`` 会强制）：
1. 回执签名与 ``envelope_core`` 摘要；
2. 核心字段与本地期望完全一致；
3. HPKE 解封得到 32 字节 ``K_pkg``。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import hpke
from ..errors import ValidationError
from ..util.canonical import b64u_encode, sha256_hex
from ..util.ids import GRANT_ID_BYTES, PKG_ID_BYTES, REQUEST_ID_BYTES, is_hex_id
from ..version import ENVELOPE_FORMAT, PROTOCOL_VERSION
from .receipt import verify_receipt
from .signing import envelope_info, require_b64, require_int, require_str
from ..crypto.memsec import wipe

__all__ = [
    "Envelope",
    "CORE_FIELDS",
    "make_envelope_core",
    "make_envelope",
    "verify_envelope_binding",
    "open_envelope",
]

CORE_FIELDS = {
    "format",
    "version",
    "package_id",
    "grant_id",
    "request_id",
    "recipient_pk_hash",
    "config_version",
    "key_id",
    "hpke_enc",
    "ciphertext",
}


@dataclass(frozen=True)
class Envelope:
    core: dict
    receipt: dict

    def to_dict(self) -> dict:
        return {"envelope_core": self.core, "receipt": self.receipt}


def make_envelope_core(
    *,
    k_pkg: bytes,
    package_id: str,
    grant_id: str,
    request_id: str,
    recipient_public_key: bytes,
    config_version: int,
    broker_key_id: str,
) -> dict:
    if len(k_pkg) != 32:
        raise ValidationError("K_pkg 必须是 32 字节")
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    if not is_hex_id(grant_id, GRANT_ID_BYTES):
        raise ValidationError("grant_id 格式非法")
    if not is_hex_id(request_id, REQUEST_ID_BYTES):
        raise ValidationError("request_id 格式非法")
    recipient_hash = sha256_hex(recipient_public_key)
    info = envelope_info(
        bytes.fromhex(package_id),
        bytes.fromhex(grant_id),
        bytes.fromhex(request_id),
        bytes.fromhex(recipient_hash),
        config_version,
    )
    wrapped = hpke.seal(recipient_public_key, k_pkg, info)
    enc, ct = hpke.split_wrap(wrapped)
    return {
        "format": ENVELOPE_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "grant_id": grant_id,
        "request_id": request_id,
        "recipient_pk_hash": recipient_hash,
        "config_version": int(config_version),
        "key_id": broker_key_id,
        "hpke_enc": b64u_encode(enc),
        "ciphertext": b64u_encode(ct),
    }


def make_envelope(*, core: dict, broker_signing_private: bytes, issued_at: int) -> Envelope:
    from .receipt import make_receipt

    return Envelope(core, make_receipt(core, broker_signing_private, issued_at=issued_at))


def verify_envelope_binding(
    core: dict,
    *,
    package_id: str,
    grant_id: str,
    request_id: str,
    recipient_public_key: bytes | None,
    recipient_pk_hash: str | None,
    config_version: int,
    broker_key_id: str | None = None,
) -> None:
    if not isinstance(core, dict) or set(core.keys()) != CORE_FIELDS:
        raise ValidationError("信封核心字段集合非法")
    if core.get("format") != ENVELOPE_FORMAT or core.get("version") != PROTOCOL_VERSION:
        raise ValidationError("信封版本非法")
    if core.get("package_id") != package_id:
        raise ValidationError("信封 package_id 不匹配")
    if core.get("grant_id") != grant_id:
        raise ValidationError("信封 grant_id 不匹配")
    if core.get("request_id") != request_id:
        raise ValidationError("信封 request_id 不匹配")
    expected_hash = (
        sha256_hex(recipient_public_key)
        if recipient_public_key is not None
        else recipient_pk_hash
    )
    if expected_hash is None or core.get("recipient_pk_hash") != expected_hash:
        raise ValidationError("信封接收方公钥摘要不匹配")
    if int(core.get("config_version", -1)) != int(config_version):
        raise ValidationError("信封 config_version 不匹配")
    if broker_key_id is not None and core.get("key_id") != broker_key_id:
        raise ValidationError("信封代理 key_id 不匹配")
    require_b64(core.get("hpke_enc"), "hpke_enc", 32)
    ct = require_b64(core.get("ciphertext"), "ciphertext")
    if len(ct) != 48:
        raise ValidationError("信封密文长度非法")


def open_envelope(
    envelope: dict,
    *,
    recipient_private_key: bytes,
    broker_signing_public: bytes,
    package_id: str,
    grant_id: str,
    request_id: str,
    config_version: int,
    broker_key_id: str | None = None,
) -> bytearray:
    if not isinstance(envelope, dict) or set(envelope.keys()) != {"envelope_core", "receipt"}:
        raise ValidationError("信封结构非法")
    core = envelope["envelope_core"]
    receipt = envelope["receipt"]
    if not isinstance(core, dict):
        raise ValidationError("信封核心必须是 JSON 对象")
    if not isinstance(receipt, dict):
        raise ValidationError("回执必须是 JSON 对象")
    verify_receipt(core, receipt, broker_signing_public)
    verify_envelope_binding(
        core,
        package_id=package_id,
        grant_id=grant_id,
        request_id=request_id,
        recipient_public_key=None,
        recipient_pk_hash=sha256_hex(
            hpke_public_from_private(recipient_private_key)
        ),
        config_version=config_version,
        broker_key_id=broker_key_id,
    )
    enc = require_b64(core["hpke_enc"], "hpke_enc", 32)
    ct = require_b64(core["ciphertext"], "ciphertext")
    info = envelope_info(
        bytes.fromhex(package_id),
        bytes.fromhex(grant_id),
        bytes.fromhex(request_id),
        bytes.fromhex(core["recipient_pk_hash"]),
        config_version,
    )
    try:
        raw = hpke.open_sealed(recipient_private_key, enc + ct, info)
    except hpke.DecryptionFailed as exc:
        raise ValidationError("信封解封失败") from exc
    if len(raw) != 32:
        raise ValidationError("信封中的 K_pkg 长度非法")
    return bytearray(raw)


def hpke_public_from_private(private_bytes: bytes) -> bytes:
    from ..crypto.hpke import public_from_private

    return public_from_private(private_bytes)
