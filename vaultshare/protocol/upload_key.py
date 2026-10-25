"""上传凭据：把 ``K_pkg`` 密封给发送方，供之后的上传步骤使用。

加密工具只负责加密，不知道口令数量、次数与有效期；因此它不能在打包时生成
KeyConfig/Policy。它把 ``K_pkg`` 用发送方身份中的 X25519 公钥 HPKE 密封，写入
``upload-key.json``。上传步骤用发送方身份私钥解封 ``K_pkg``，再按此时选定的
口令策略生成 Policy/KeyConfig。

安全性质：

* 文件本身不含明文 ``K_pkg``，单独拿到文件无法解密或伪造分享；
* 密封上下文绑定 package_id、容器摘要、发送方身份与服务器地址；
* 记录由发送方 Ed25519 签名，上传步骤会验证签名与身份绑定；
* 上传步骤仍需要发送方身份私钥（用于解封与签名），这是有意的：长期签名密钥
  不会被复制进上传凭据。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import hpke
from ..crypto.keys import (
    DOMAIN_UPLOAD_KEY,
    Ed25519Keys,
    sign_object,
    verify_object,
)
from ..errors import ValidationError
from ..util.canonical import b64u_encode
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..util.serverurl import normalize_server_url
from ..version import PROTOCOL_VERSION, UPLOAD_KEY_FORMAT
from .identity import SenderIdentity, check_sender_binding
from .signing import require_b64, require_int, require_str, upload_key_info

__all__ = [
    "UPLOAD_KEY_FORMAT",
    "UploadKeyParsed",
    "build_upload_key",
    "verify_upload_key",
    "open_upload_key",
]

_SUITE = hpke.SUITE_NAME
_ALLOWED = {
    "format",
    "version",
    "package_id",
    "server",
    "payload_sha256",
    "suite",
    "sender_key_id",
    "sender_identity_hash",
    "sender_public_key",
    "hpke_wrap",
    "created_at",
    "signature",
}


@dataclass(frozen=True)
class UploadKeyParsed:
    record: dict
    package_id: str
    server: str
    payload_sha256: str
    sender_identity_hash: str
    sender_public_key: bytes
    sender: SenderIdentity | None


def _info(parsed_package_id: str, payload_sha256: str, sender_hash: str, server: str) -> bytes:
    return upload_key_info(
        bytes.fromhex(parsed_package_id),
        bytes.fromhex(payload_sha256),
        bytes.fromhex(sender_hash),
        server.encode("utf-8"),
    )


def build_upload_key(
    *,
    package_id: str,
    server: str,
    payload_sha256: str,
    sender: SenderIdentity,
    signer_private: bytes,
    k_pkg: bytes,
    created_at: int,
) -> dict:
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    normalized = normalize_server_url(server)
    if not normalized:
        raise ValidationError("上传凭据必须包含服务器地址")
    if not is_hex_id(payload_sha256, 32):
        raise ValidationError("payload_sha256 格式非法")
    if len(k_pkg) != 32:
        raise ValidationError("K_pkg 必须是 32 字节")
    wrapped = hpke.seal(
        sender.x25519_public,
        bytes(k_pkg),
        _info(package_id, payload_sha256, sender.digest, normalized),
    )
    enc, ciphertext = hpke.split_wrap(wrapped)
    record = {
        "format": UPLOAD_KEY_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "server": normalized,
        "payload_sha256": payload_sha256,
        "suite": _SUITE,
        "sender_key_id": sender.sender_key_id,
        "sender_identity_hash": sender.digest,
        "sender_public_key": b64u_encode(sender.ed25519_public),
        "hpke_wrap": {"enc": b64u_encode(enc), "ciphertext": b64u_encode(ciphertext)},
        "created_at": int(created_at),
    }
    return sign_object(
        Ed25519Keys.from_private(signer_private), DOMAIN_UPLOAD_KEY, record
    )


def verify_upload_key(record: dict, identity: SenderIdentity | None = None) -> UploadKeyParsed:
    if not isinstance(record, dict):
        raise ValidationError("上传凭据必须是 JSON 对象")
    if record.get("format") != UPLOAD_KEY_FORMAT:
        raise ValidationError("上传凭据格式标识不匹配")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的上传凭据版本")
    if set(record.keys()) != _ALLOWED:
        raise ValidationError("上传凭据字段集合非法")

    package_id = require_str(record.get("package_id"), "package_id", max_len=32)
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("上传凭据的 package_id 格式非法")
    server = normalize_server_url(require_str(record.get("server"), "server", max_len=512))
    if not server:
        raise ValidationError("上传凭据缺少服务器地址")
    if server != record["server"]:
        raise ValidationError("上传凭据的服务器地址不是规范形式")
    payload_sha = require_str(record.get("payload_sha256"), "payload_sha256", max_len=64)
    if not is_hex_id(payload_sha, 32):
        raise ValidationError("上传凭据的 payload_sha256 格式非法")
    if record.get("suite") != _SUITE:
        raise ValidationError("不支持的 HPKE 套件")

    sender_public = require_b64(record.get("sender_public_key"), "sender_public_key", 32)
    if not verify_object(sender_public, DOMAIN_UPLOAD_KEY, record):
        raise ValidationError("上传凭据签名无效")
    sender_hash = require_str(
        record.get("sender_identity_hash"), "sender_identity_hash", max_len=64
    )
    if not is_hex_id(sender_hash, 32):
        raise ValidationError("上传凭据的发送方身份摘要非法")

    wrap = record.get("hpke_wrap")
    if not isinstance(wrap, dict) or set(wrap.keys()) != {"enc", "ciphertext"}:
        raise ValidationError("上传凭据的 hpke_wrap 结构非法")
    require_b64(wrap.get("enc"), "hpke_wrap.enc", 32)
    ciphertext = require_b64(wrap.get("ciphertext"), "hpke_wrap.ciphertext")
    if len(ciphertext) != 48:
        raise ValidationError("上传凭据的 hpke_wrap.ciphertext 长度非法")

    require_int(record.get("created_at"), "created_at", minimum=0)
    if identity is not None:
        check_sender_binding(record, identity)
        if sender_hash != identity.digest:
            raise ValidationError("上传凭据的发送方身份摘要不一致")
    return UploadKeyParsed(
        record=dict(record),
        package_id=package_id,
        server=server,
        payload_sha256=payload_sha,
        sender_identity_hash=sender_hash,
        sender_public_key=sender_public,
        sender=identity,
    )


def open_upload_key(
    parsed: UploadKeyParsed,
    x25519_private: bytes,
    x25519_public: bytes,
) -> bytearray:
    if parsed.sender is not None and bytes(x25519_public) != parsed.sender.x25519_public:
        raise ValidationError("发送方 X25519 公钥与上传凭据不一致")
    wrap = parsed.record["hpke_wrap"]
    enc = require_b64(wrap.get("enc"), "hpke_wrap.enc", 32)
    ciphertext = require_b64(wrap.get("ciphertext"), "hpke_wrap.ciphertext")
    info = _info(
        parsed.package_id,
        parsed.payload_sha256,
        parsed.sender_identity_hash,
        parsed.server,
    )
    try:
        raw = hpke.open_sealed(x25519_private, enc + ciphertext, info)
    except hpke.DecryptionFailed as exc:
        raise ValidationError("无法解开上传凭据（发送方身份或文件不匹配）") from exc
    if len(raw) != 32:
        raise ValidationError("上传凭据解出的 K_pkg 长度非法")
    return bytearray(raw)
