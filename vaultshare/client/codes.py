"""解开代理封给发送方的口令密文。

密封使用发送方身份记录中绑定的 X25519 公钥；服务器从未见过明文。命令行只在
本地用私钥解开并打印，解出的口令不落盘。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import hpke
from ..errors import ValidationError
from ..protocol.signing import code_info, require_b64
from ..util.base32c import format_code, normalize_code

__all__ = ["SealedCode", "open_sealed_code"]


@dataclass(frozen=True)
class SealedCode:
    grant_id: str
    code: str
    formatted: str


def open_sealed_code(
    package_id: str,
    grant_id: str,
    sealed: dict,
    x25519_private: bytes,
    x25519_public: bytes,
) -> SealedCode:
    if not isinstance(sealed, dict) or set(sealed.keys()) != {"enc", "ciphertext"}:
        raise ValidationError("sealed_code 结构非法")
    enc = require_b64(sealed.get("enc"), "sealed_code.enc", 32)
    ct = require_b64(sealed.get("ciphertext"), "sealed_code.ciphertext")
    info = code_info(
        bytes.fromhex(package_id),
        bytes.fromhex(grant_id),
        x25519_public,
    )
    try:
        raw = hpke.open_sealed(x25519_private, enc + ct, info)
    except hpke.DecryptionFailed as exc:
        raise ValidationError("无法解开口令密文（发送方私钥不匹配）") from exc
    try:
        code = normalize_code(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError("口令密文内容非法") from exc
    return SealedCode(grant_id=grant_id, code=code, formatted=format_code(code))
