"""服务器侧兑换状态机：预授权 → 提交预留 → 验证预留后交付。

关键安全性质
============
* **额度只在预留事务提交时扣减**，且永不回滚。代理拒绝交付、网络失败、
  磁盘失败都不会恢复次数。
* 同一 ``request_id`` 的重试先看状态：``DELIVERED`` 直接返回缓存信封；
  ``RESERVED`` 只重新交付，不再扣减。
* 代理交付前会自行读取 state.json 并核对已提交的预留记录——服务端的
  “口头承诺”不够。
* 两个不同 ``request_id`` 并发抢最后一个名额时，预留事务串行化，后者在锁内
  看到 ``used == max_uses`` 而被拒绝。
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from ..broker.service import TICKET_TTL, verify_ticket
from ..errors import (
    Conflict,
    Forbidden,
    Gone,
    IpcError,
    NotFound,
    Unavailable,
    ValidationError,
    VaultShareError,
)
from ..protocol.grants import validate_grant_record
from ..protocol.policy import check_redemption, grant_metrics
from ..protocol.redeem import recipient_pk_hash
from ..protocol.signing import require_b64
from ..storage.state import envelope_digest
from ..util.canonical import b64u_decode, b64u_encode, canonical_bytes
from ..util.ids import GRANT_ID_BYTES, PKG_ID_BYTES, REQUEST_ID_BYTES, is_hex_id, new_hex_id
from ..util.timeutil import now
from .package_checks import load_package_context

__all__ = ["redeem", "RedeemOutcome"]

MAX_ATTEMPTS = 4


class _Retry(Exception):
    pass


@dataclass(frozen=True)
class RedeemOutcome:
    envelope: dict
    request_id: str
    replayed: bool


def _validate_outer(outer: dict) -> tuple[str, str]:
    if not isinstance(outer, dict):
        raise ValidationError("兑换请求必须是 JSON 对象")
    request_id = outer.get("request_id")
    package_id = outer.get("package_id")
    if not is_hex_id(request_id, REQUEST_ID_BYTES):
        raise ValidationError("request_id 格式非法")
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    return request_id, package_id


def _ticket_signing_public(context, package_id: str) -> tuple[bytes, str]:
    snapshot = context.store.snapshot()
    ctx = load_package_context(
        context.settings, snapshot["body"], package_id, require_active=True, require_payload=True
    )
    return require_b64(ctx.keyconfig["broker"]["signing_public_key"], "signing_public_key", 32), ctx.keyconfig["broker"]["key_id"]


def _outer_digest_b64(outer: dict) -> str:
    return b64u_encode(canonical_bytes(outer))


def _same_outer(record: dict, outer: dict) -> bool:
    stored = record.get("opaque_request")
    return isinstance(stored, str) and hmac.compare_digest(
        stored, _outer_digest_b64(outer)
    )


def _invalid_code() -> Forbidden:
    """口令不存在与口令不可用（过期/撤销/用尽）必须给出完全相同的响应。

    只要两种情况的 ``error``/``message``/状态码有任何差异，拿到分享包的人就能
    用“这个口令是不是存在”来做枚举，因此对外一律表现为“口令无效”。真实的
    失败原因只会写进代理侧审计日志。
    """
    return Forbidden("口令无效", code="invalid_code")


def _map_broker_error(exc: IpcError) -> VaultShareError:
    code = exc.code
    if code == "state_changed":
        return _Retry()
    if code in ("invalid_code", "grant_expired", "grant_exhausted", "grant_revoked"):
        return _invalid_code()
    if code == "package_revoked":
        return Gone("授权已不可用", code=code)
    if code in ("sender_revoked", "package_inactive", "sender_unknown"):
        return Forbidden("该分享包已停用", code=code)
    if code in ("reservation_missing", "reservation_invalid"):
        return _Retry()
    return Unavailable("密钥代理暂不可用，请稍后重试", code="broker_unavailable")


def redeem(context, outer: dict) -> RedeemOutcome:
    if context.store.degraded:
        raise Unavailable("状态处于降级模式，兑换已暂停", code="state_corrupt")
    request_id, package_id = _validate_outer(outer)

    for _attempt in range(MAX_ATTEMPTS):
        snapshot = context.store.snapshot()
        body = snapshot["body"]
        existing = body.get("requests", {}).get(request_id)
        if existing is not None:
            if not _same_outer(existing, outer):
                raise Conflict(
                    "同一 request_id 携带了不同的请求内容", code="request_id_reuse"
                )
            if existing.get("status") == "DELIVERED":
                envelope = {
                    "envelope_core": existing.get("envelope_core"),
                    "receipt": existing.get("receipt"),
                }
                if not isinstance(envelope["envelope_core"], dict) or not isinstance(
                    envelope["receipt"], dict
                ):
                    raise Unavailable("已交付记录缺少信封，请人工检查状态", code="state_corrupt")
                return RedeemOutcome(envelope, request_id, True)
            if existing.get("status") == "RESERVED":
                try:
                    return _deliver_reserved(context, outer, existing)
                except _Retry:
                    continue
            if existing.get("status") == "DENIED":
                raise Forbidden("该请求已被拒绝", code="request_denied")

        # 预授权（不持锁、不写状态）
        try:
            load_package_context(
                context.settings,
                body,
                package_id,
                require_active=True,
                require_payload=True,
            )
            ticket = context.broker.call(
                "authorize",
                {
                    "outer": outer,
                    "state_generation": snapshot["generation"],
                    "state_digest": envelope_digest(snapshot),
                },
            )["ticket"]
        except IpcError as exc:
            mapped = _map_broker_error(exc)
            if isinstance(mapped, _Retry):
                continue
            raise mapped from exc
        except (KeyError, TypeError) as exc:
            raise Unavailable("密钥代理返回格式非法", code="broker_error") from exc

        try:
            outcome = _reserve_and_deliver(context, outer, ticket, snapshot)
        except _Retry:
            continue
        if outcome is not None:
            return outcome
    raise Unavailable("兑换请求持续冲突，请稍后重试", code="conflict")


def _verify_ticket_binding(ticket: dict, outer: dict, package_id: str, signing_public: bytes) -> None:
    verify_ticket(ticket, signing_public)
    if ticket.get("request_id") != outer.get("request_id"):
        raise Conflict("票据 request_id 不匹配", code="ticket_mismatch")
    if ticket.get("package_id") != package_id:
        raise Conflict("票据 package_id 不匹配", code="ticket_mismatch")


def _reserve_and_deliver(context, outer: dict, ticket: dict, snapshot: dict) -> RedeemOutcome | None:
    request_id = outer["request_id"]
    package_id = outer["package_id"]
    signing_public, broker_key_id = _ticket_signing_public(context, package_id)
    _verify_ticket_binding(ticket, outer, package_id, signing_public)

    ctx = load_package_context(
        context.settings,
        snapshot["body"],
        package_id,
        require_active=True,
        require_payload=True,
    )
    policy = ctx.policy_parsed
    now_ts = now()

    def reserve(body: dict, generation: int):
        existing = body["requests"].get(request_id)
        if existing is not None:
            return {"exists": True, "record": existing}
        package = body["packages"].get(package_id)
        if not isinstance(package, dict) or package.get("status") != "active":
            raise ValidationError("package 已停用", code="package_inactive")
        grant = body["grants"].get(ticket["grant_id"])
        if not isinstance(grant, dict):
            raise ValidationError("授权不存在", code="grant_unknown")
        validate_grant_record(grant)
        if grant.get("package_id") != package_id:
            raise Conflict("授权与 package 不匹配", code="grant_mismatch")
        if grant.get("policy_version") != policy.policy_version:
            raise Conflict("授权版本与策略不一致", code="policy_mismatch")
        # 以下状态都意味着“口令存在但不可用”，对外一律与不存在的口令同响应。
        if grant.get("revoked"):
            raise _invalid_code()
        if int(grant.get("expires_at", 0)) < now_ts:
            raise _invalid_code()
        if int(grant.get("used", 0)) >= int(grant.get("max_uses", 0)):
            raise _invalid_code()
        metrics = grant_metrics(body["grants"], package_id)
        if metrics["used"] + 1 > policy.max_total_redemptions:
            raise _invalid_code()
        if metrics["allocated_uses"] > policy.max_total_redemptions:
            raise Conflict("状态中的分配额度超过策略上限", code="state_inconsistent")

        grant["used"] = int(grant.get("used", 0)) + 1
        metrics = grant_metrics(body["grants"], package_id)
        body["grants_counters"][package_id] = metrics
        reservation_id = new_hex_id(16)
        record = {
            "package_id": package_id,
            "grant_id": ticket["grant_id"],
            "recipient_pk_hash": ticket["recipient_pk_hash"],
            "status": "RESERVED",
            "authorization_id": ticket["authorization_id"],
            "reservation_id": reservation_id,
            "state_generation": int(generation),
            "reserved_at": now_ts,
            "delivered_at": 0,
            "opaque_request": _outer_digest_b64(outer),
            "ticket": ticket,
            "envelope_core": None,
            "receipt": None,
        }
        body["requests"][request_id] = record
        return {"exists": False, "record": record}

    result = context.store.transaction(reserve, with_generation=True)
    record = result["record"]
    if record.get("status") == "DELIVERED":
        envelope = {"envelope_core": record.get("envelope_core"), "receipt": record.get("receipt")}
        return RedeemOutcome(envelope, request_id, True)
    if record.get("status") != "RESERVED":
        raise _Retry()
    try:
        return _deliver_reserved(context, outer, record)
    except _Retry:
        # 可能是并发者已经提交 DELIVERED，或预留尚未可见；交给外层重读状态。
        return None


def _deliver_reserved(context, outer: dict, record: dict) -> RedeemOutcome:
    request_id = outer["request_id"]
    package_id = outer["package_id"]
    if not _same_outer(record, outer):
        raise Conflict("同一 request_id 携带了不同的请求内容", code="request_id_reuse")
    signing_public, broker_key_id = _ticket_signing_public(context, package_id)
    ticket = record.get("ticket")
    if not isinstance(ticket, dict):
        raise Unavailable("预留记录缺少票据", code="state_corrupt")
    record_recipient_hash = record.get("recipient_pk_hash")

    current = now()
    if int(ticket.get("expires_at", 0)) < current:
        try:
            fresh = context.broker.call(
                "authorize",
                {
                    "outer": outer,
                    "state_generation": context.store.snapshot()["generation"],
                    "state_digest": envelope_digest(context.store.snapshot()),
                },
            )["ticket"]
            verify_ticket(fresh, signing_public)
            if fresh.get("grant_id") != record.get("grant_id"):
                raise Conflict("重新预授权返回了不同的授权", code="ticket_mismatch")
            if fresh.get("recipient_pk_hash") != record_recipient_hash:
                raise Conflict("重新预授权返回了不同的接收方", code="ticket_mismatch")

            def update(body: dict):
                rec = body["requests"].get(request_id)
                if not isinstance(rec, dict):
                    raise _Retry()
                if rec.get("status") == "DELIVERED":
                    return {"delivered": True, "record": rec}
                if rec.get("status") != "RESERVED":
                    raise _Retry()
                if rec.get("reservation_id") != record.get("reservation_id"):
                    raise _Retry()
                rec["ticket"] = fresh
                rec["authorization_id"] = fresh["authorization_id"]
                body["requests"][request_id] = rec
                return {"delivered": False, "record": rec}

            updated = context.store.transaction(update)
            if updated["delivered"]:
                rec = updated["record"]
                return RedeemOutcome(
                    {
                        "envelope_core": rec.get("envelope_core"),
                        "receipt": rec.get("receipt"),
                    },
                    request_id,
                    True,
                )
            record = updated["record"]
            ticket = record["ticket"]
        except IpcError as exc:
            mapped = _map_broker_error(exc)
            if isinstance(mapped, _Retry):
                raise _Retry() from exc
            if isinstance(mapped, Gone):
                # 预留已提交，但代理认为授权不可用：保留额度，交由人工检查。
                raise Unavailable(
                    "预留已提交但重新预授权失败，请联系管理员",
                    code="reservation_stuck",
                ) from exc
            raise mapped from exc

    try:
        delivered = context.broker.call(
            "deliver",
            {
                "outer": outer,
                "ticket": ticket,
                "reservation_id": record["reservation_id"],
            },
        )
        envelope = delivered["envelope"]
    except IpcError as exc:
        if exc.code == "ticket_expired":
            raise _Retry() from exc
        mapped = _map_broker_error(exc)
        if isinstance(mapped, _Retry):
            raise _Retry() from exc
        raise mapped from exc
    except (KeyError, TypeError) as exc:
        raise Unavailable("密钥代理返回格式非法", code="broker_error") from exc

    if not isinstance(envelope, dict):
        raise Unavailable("密钥代理返回的信封格式非法", code="broker_error")

    def mark_delivered(body: dict):
        rec = body["requests"].get(request_id)
        if not isinstance(rec, dict):
            raise _Retry()
        if rec.get("status") == "DELIVERED":
            return {
                "envelope_core": rec.get("envelope_core"),
                "receipt": rec.get("receipt"),
                "replayed": True,
            }
        if rec.get("status") != "RESERVED":
            raise _Retry()
        if rec.get("reservation_id") != record.get("reservation_id"):
            raise _Retry()
        rec["status"] = "DELIVERED"
        rec["delivered_at"] = now()
        rec["envelope_core"] = envelope["envelope_core"]
        rec["receipt"] = envelope["receipt"]
        body["requests"][request_id] = rec
        return {"envelope_core": rec["envelope_core"], "receipt": rec["receipt"], "replayed": False}

    try:
        stored = context.store.transaction(mark_delivered)
    except VaultShareError:
        # 信封已经由代理缓存；客户端重试会命中 RESERVED 并再次交付。
        raise Unavailable("交付已生成但状态提交失败，请重试", code="commit_failed")
    return RedeemOutcome(
        {"envelope_core": stored["envelope_core"], "receipt": stored["receipt"]},
        request_id,
        bool(stored.get("replayed")),
    )
