"""SharePolicy 与累计额度校验。

累计校验必须在**同一把状态锁内、基于整个包的全部授权**重新计算，而不是只看
本次请求。否则攻击者可以把 100 次兑换拆成 10 批、每批看起来都合法。

``allow_export`` 被刻意移除：接收方拿到 ``K_pkg`` 后无法被远程限制导出，
保留该字段只会制造虚假的安全承诺。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.keys import DOMAIN_POLICY, sign_object, verify_object
from ..errors import ValidationError
from ..util.canonical import b64u_encode, canonical_bytes, sha256_bytes
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..version import POLICY_FORMAT, PROTOCOL_VERSION
from .identity import SenderIdentity, check_policy_binding
from .signing import require_int, require_str

__all__ = [
    "SharePolicy",
    "build_policy",
    "verify_policy",
    "policy_digest",
    "grant_metrics",
    "check_new_grants",
    "check_redemption",
]

_ALLOWED = {
    "format",
    "version",
    "package_id",
    "max_codes",
    "max_uses_per_code",
    "max_total_redemptions",
    "allow_any_recipient",
    "latest_expiry",
    "policy_version",
    "sender_key_id",
    "sender_identity_hash",
    "sender_public_key",
    "created_at",
    "signature",
}


@dataclass(frozen=True)
class SharePolicy:
    record: dict
    package_id: str
    policy_hash: str
    max_codes: int
    max_uses_per_code: int
    max_total_redemptions: int
    latest_expiry: int
    policy_version: int
    sender: SenderIdentity


def policy_digest(record: dict) -> str:
    return sha256_bytes(canonical_bytes(record)).hex()


def build_policy(
    package_id: str,
    sender: SenderIdentity,
    signer_private: bytes,
    *,
    max_codes: int,
    max_uses_per_code: int,
    max_total_redemptions: int,
    latest_expiry: int,
    created_at: int,
    policy_version: int = 1,
) -> dict:
    from ..crypto.keys import Ed25519Keys

    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    record = {
        "format": POLICY_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "max_codes": int(max_codes),
        "max_uses_per_code": int(max_uses_per_code),
        "max_total_redemptions": int(max_total_redemptions),
        "allow_any_recipient": True,
        "latest_expiry": int(latest_expiry),
        "policy_version": int(policy_version),
        "sender_key_id": sender.sender_key_id,
        "sender_identity_hash": sender.digest,
        "sender_public_key": b64u_encode(sender.ed25519_public),
        "created_at": int(created_at),
    }
    signed = sign_object(Ed25519Keys.from_private(signer_private), DOMAIN_POLICY, record)
    return verify_policy(signed, sender).record


def verify_policy(record: dict, identity: SenderIdentity | None = None) -> SharePolicy:
    if not isinstance(record, dict):
        raise ValidationError("Policy 必须是 JSON 对象")
    if record.get("format") != POLICY_FORMAT:
        raise ValidationError("Policy 格式标识不匹配")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的 Policy 版本")
    if set(record.keys()) != _ALLOWED:
        raise ValidationError("Policy 字段集合非法")
    package_id = require_str(record.get("package_id"), "package_id", max_len=32)
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("Policy.package_id 格式非法")
    max_codes = require_int(record.get("max_codes"), "max_codes", 1, 10_000)
    per_code = require_int(record.get("max_uses_per_code"), "max_uses_per_code", 1, 1_000_000)
    total = require_int(
        record.get("max_total_redemptions"), "max_total_redemptions", 1, 1_000_000_000
    )
    if per_code > total:
        raise ValidationError("max_uses_per_code 不能大于 max_total_redemptions")
    if record.get("allow_any_recipient") is not True:
        raise ValidationError("当前版本只支持 allow_any_recipient=true")
    latest = require_int(record.get("latest_expiry"), "latest_expiry", 1)
    policy_version = require_int(record.get("policy_version"), "policy_version", 1)
    created_at = require_int(record.get("created_at"), "created_at", 0)
    if latest <= created_at:
        raise ValidationError("latest_expiry 必须晚于 created_at")
    sender_pub = record.get("sender_public_key")
    from .signing import require_b64

    sender_raw = require_b64(sender_pub, "sender_public_key", 32)
    if not verify_object(sender_raw, DOMAIN_POLICY, record):
        raise ValidationError("Policy 签名无效")
    if identity is not None:
        check_policy_binding(record, identity)
    # identity=None 时只完成签名验证；调用方必须把 sender_key_id /
    # sender_identity_hash / sender_public_key 与已注册身份逐项比对。
    return SharePolicy(
        record=record,
        package_id=package_id,
        policy_hash=policy_digest(record),
        max_codes=max_codes,
        max_uses_per_code=per_code,
        max_total_redemptions=total,
        latest_expiry=latest,
        policy_version=policy_version,
        sender=identity,
    )


def grant_metrics(grants: dict, package_id: str) -> dict:
    """从 grant 记录重新计算累计值。server 只用它，不信任缓存计数器。"""
    issued = allocated = used = 0
    for grant in grants.values():
        if not isinstance(grant, dict) or grant.get("package_id") != package_id:
            continue
        if grant.get("revoked"):
            # 已撤销的口令仍占用已签发/已分配额度，但不允许再消费。
            pass
        issued += 1
        allocated += int(grant.get("max_uses", 0))
        used += int(grant.get("used", 0))
    return {"issued": issued, "allocated_uses": allocated, "used": used}


def check_new_grants(
    policy: SharePolicy,
    grants: dict,
    *,
    count: int,
    uses_per_code: int,
    expires_at: int,
) -> dict:
    """在状态锁内调用。任何一项超限都抛异常，调用方不得部分提交。"""
    if count < 1:
        raise ValidationError("至少创建一个口令")
    if uses_per_code < 1 or uses_per_code > policy.max_uses_per_code:
        raise ValidationError("uses_per_code 超过策略允许值")
    if expires_at > policy.latest_expiry:
        raise ValidationError("口令过期时间超过策略上限")
    if expires_at <= 0:
        raise ValidationError("口令过期时间非法")
    metrics = grant_metrics(grants, policy.package_id)
    if metrics["issued"] + count > policy.max_codes:
        raise ValidationError("签发口令数将超过 max_codes", code="quota_denied")
    if (
        metrics["allocated_uses"] + count * uses_per_code
        > policy.max_total_redemptions
    ):
        raise ValidationError(
            "分配额度将超过 max_total_redemptions", code="quota_denied"
        )
    if metrics["used"] > metrics["allocated_uses"]:
        raise ValidationError("状态不一致：已消费次数大于已分配额度", code="state_inconsistent")
    if metrics["used"] > policy.max_total_redemptions:
        raise ValidationError("状态不一致：已消费次数超过策略上限", code="state_inconsistent")
    return metrics


def check_redemption(policy: SharePolicy, grant: dict, *, now: int) -> None:
    """代理与服务器都调用的兑换前置检查。"""
    if grant.get("revoked"):
        raise ValidationError("口令已撤销", code="grant_revoked")
    if int(grant.get("expires_at", 0)) < now:
        raise ValidationError("口令已过期", code="grant_expired")
    used = int(grant.get("used", 0))
    max_uses = int(grant.get("max_uses", 0))
    if used < 0 or max_uses < 1:
        raise ValidationError("授权记录非法")
    if used >= max_uses:
        raise ValidationError("口令使用次数已耗尽", code="grant_exhausted")
