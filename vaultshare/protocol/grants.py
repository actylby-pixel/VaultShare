"""兑换授权（grant）与口令验证值。

服务器只保存 ``HMAC-SHA256(code_mac_key, 归一化口令)``。``code_mac_key`` 只由
代理持有，因此即使 Web 进程被完整读取，也无法离线爆破口令（26 个 Crockford
字符 = 130 bit，且 HMAC 需要密钥）。

明文口令只在代理内存里短暂存在，随即用发送方身份记录里的 X25519 公钥封住。
``sealed_code`` 是唯一离开代理的形式。
"""

from __future__ import annotations

from ..errors import ValidationError
from ..util.canonical import b64u_encode, hmac_sha256
from ..util.ids import GRANT_ID_BYTES, PKG_ID_BYTES, is_hex_id
from ..util.base32c import is_valid_code, normalize_code
from .signing import require_int, require_str

__all__ = [
    "code_verifier",
    "verify_code",
    "make_grant",
    "validate_grant_record",
    "GRANT_FIELDS",
]

GRANT_FIELDS = {
    "grant_id",
    "package_id",
    "code_verifier",
    "sealed_code",
    "expires_at",
    "max_uses",
    "used",
    "revoked",
    "policy_version",
    "batch_id",
    "created_at",
}


def code_verifier(code: str, code_mac_key: bytes) -> str:
    normalized = normalize_code(code)
    if not is_valid_code(normalized):
        raise ValidationError("口令格式非法", code="invalid_code")
    return hmac_sha256(code_mac_key, normalized.encode("ascii")).hex()


def verify_code(code: str, expected_verifier: str, code_mac_key: bytes) -> bool:
    try:
        candidate = code_verifier(code, code_mac_key)
    except ValidationError:
        return False
    import hmac

    return hmac.compare_digest(candidate, expected_verifier)


def make_grant(
    *,
    grant_id: str,
    package_id: str,
    code_verifier_hex: str,
    sealed_code: dict,
    expires_at: int,
    max_uses: int,
    policy_version: int,
    batch_id: str,
    created_at: int,
) -> dict:
    grant = {
        "grant_id": grant_id,
        "package_id": package_id,
        "code_verifier": code_verifier_hex,
        "sealed_code": sealed_code,
        "expires_at": int(expires_at),
        "max_uses": int(max_uses),
        "used": 0,
        "revoked": False,
        "policy_version": int(policy_version),
        "batch_id": batch_id,
        "created_at": int(created_at),
    }
    validate_grant_record(grant)
    return grant


def validate_grant_record(grant: dict) -> None:
    if not isinstance(grant, dict) or set(grant.keys()) != GRANT_FIELDS:
        raise ValidationError("授权记录字段集合非法")
    if not is_hex_id(grant.get("grant_id"), GRANT_ID_BYTES):
        raise ValidationError("grant_id 格式非法")
    if not is_hex_id(grant.get("package_id"), PKG_ID_BYTES):
        raise ValidationError("授权记录的 package_id 格式非法")
    if not is_hex_id(grant.get("code_verifier"), 32):
        raise ValidationError("code_verifier 格式非法")
    sealed = grant.get("sealed_code")
    if not isinstance(sealed, dict) or set(sealed.keys()) != {"enc", "ciphertext"}:
        raise ValidationError("sealed_code 结构非法")
    require_int(grant.get("expires_at"), "expires_at", 1)
    require_int(grant.get("max_uses"), "max_uses", 1, 1_000_000)
    require_int(grant.get("used"), "used", 0, 1_000_000)
    if grant["used"] > grant["max_uses"]:
        raise ValidationError("授权已消费次数大于上限")
    if not isinstance(grant.get("revoked"), bool):
        raise ValidationError("revoked 必须是布尔值")
    require_int(grant.get("policy_version"), "policy_version", 1)
    require_str(grant.get("batch_id"), "batch_id", max_len=64)
    require_int(grant.get("created_at"), "created_at", 0)
