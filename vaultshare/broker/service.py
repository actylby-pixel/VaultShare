"""软件密钥代理：``KeyBroker`` 的本地进程实现。

抽象边界
========
``KeyBroker`` 只定义 Web 进程能发起的操作。未来用 TEE/HSM 替换时，只要保持
操作与返回结构不变，服务器、协议与客户端都不需要改。**当前实现是普通软件
进程，不是 TEE**：拥有管理员权限的攻击者仍可读取密钥文件或控制进程。

代理对每次 ``deliver`` 都会：
1. 验票据签名、字段、有效期；
2. **只读打开 state.json，验证完整信封 MAC**；
3. 要求存在与票据完全匹配的 ``RESERVED`` 记录（request_id、grant_id、
   recipient_pk_hash、authorization_id、reservation_id）；
4. 只有以上全部通过，才解封 ``K_pkg`` 并重封给接收方。
"""

from __future__ import annotations

import abc
import hmac
from dataclasses import dataclass

from ..config import Settings
from ..crypto import hpke
from ..crypto.keys import DOMAIN_AUTHORIZATION, Ed25519Keys, sign_object, verify_object
from ..crypto.memsec import wipe
from ..errors import Conflict, NotFound, Unavailable, ValidationError
from ..protocol.envelope import make_envelope, make_envelope_core
from ..protocol.grants import code_verifier, make_grant, validate_grant_record
from ..protocol.identity import verify_broker_identity
from ..protocol.keyconfig import open_package_key, verify_keyconfig
from ..protocol.policy import (
    check_new_grants,
    check_redemption,
    policy_digest,
    verify_policy,
)
from ..protocol.redeem import open_redeem_request, recipient_pk_hash
from ..protocol.signing import require_int, require_str
from ..storage.audit import AuditLog
from ..storage.package_store import read_keyconfig_bytes, read_policy_bytes
from ..storage.state import envelope_digest, read_verified_state
from ..util.base32c import format_code, generate_code
from ..util.canonical import canonical_bytes, sha256_hex
from ..util.ids import (
    GRANT_ID_BYTES,
    KEY_ID_BYTES,
    PKG_ID_BYTES,
    REQUEST_ID_BYTES,
    is_hex_id,
    new_hex_id,
)
from ..util.timeutil import now
from ..version import PROTOCOL_VERSION
from .envelope_cache import EnvelopeCache
from .idempotency import IdempotencyStore
from .keyring import BrokerKeys, KeyRing

__all__ = ["TICKET_FORMAT", "BrokerService", "SoftwareKeyBroker", "verify_ticket"]

TICKET_FORMAT = "vaultshare-authorization"
TICKET_TTL = 120
TICKET_FIELDS = {
    "format",
    "version",
    "authorization_id",
    "grant_id",
    "request_id",
    "recipient_pk_hash",
    "package_id",
    "policy_hash",
    "state_generation",
    "state_digest",
    "issued_at",
    "expires_at",
    "broker_key_id",
    "signature",
}


class BrokerService(abc.ABC):
    """稳定的代理接口。���换 TEE/HSM 实现时保持这些方法签名不变。"""

    @abc.abstractmethod
    def dispatch(self, op: str, body: dict, request_id: str, body_sha256: str) -> dict: ...


@dataclass(frozen=True)
class _PackageContext:
    package: dict
    keyconfig: dict
    policy: dict
    identity_entry: dict
    keys: BrokerKeys


def verify_ticket(ticket: dict, signing_public: bytes, *, current_time: int | None = None,
                  check_expiry: bool = True) -> dict:
    if not isinstance(ticket, dict) or set(ticket.keys()) != TICKET_FIELDS:
        raise ValidationError("预授权票据字段非法", code="bad_ticket")
    if ticket.get("format") != TICKET_FORMAT or ticket.get("version") != PROTOCOL_VERSION:
        raise ValidationError("预授权票据版本非法", code="bad_ticket")
    for name, nbytes in (
        ("authorization_id", 16),
        ("grant_id", GRANT_ID_BYTES),
        ("package_id", PKG_ID_BYTES),
        ("request_id", REQUEST_ID_BYTES),
        ("broker_key_id", KEY_ID_BYTES),
    ):
        value = ticket.get(name)
        if not isinstance(value, str) or not is_hex_id(value, nbytes):
            raise ValidationError(f"票据 {name} 格式非法", code="bad_ticket")
    for name in ("recipient_pk_hash", "policy_hash", "state_digest"):
        value = ticket.get(name)
        if not isinstance(value, str) or len(value) != 64:
            raise ValidationError(f"票据 {name} 格式非法", code="bad_ticket")
    require_int(ticket.get("state_generation"), "state_generation", 0)
    require_int(ticket.get("issued_at"), "issued_at", 0)
    require_int(ticket.get("expires_at"), "expires_at", 0)
    if ticket["expires_at"] <= ticket["issued_at"]:
        raise ValidationError("票据有效期非法", code="bad_ticket")
    if not verify_object(signing_public, DOMAIN_AUTHORIZATION, ticket):
        raise ValidationError("票据签名无效", code="bad_ticket")
    if check_expiry:
        current = now() if current_time is None else current_time
        if ticket["expires_at"] < current:
            raise ValidationError("票据已过期", code="ticket_expired")
        if ticket["issued_at"] > current + 60:
            raise ValidationError("票据签发时间在未来", code="bad_ticket")
    return ticket


class SoftwareKeyBroker(BrokerService):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.ensure_dirs()
        from ..storage.secrets import read_code_mac_key, read_state_mac_key

        self.state_mac_key = read_state_mac_key(settings)
        self.code_mac_key = read_code_mac_key(settings)
        self.keyring = KeyRing(settings)
        self.idempotency = IdempotencyStore(settings)
        self.cache = EnvelopeCache(settings)
        self.audit = AuditLog(str(settings.audit_path))

    # ------------------------------------------------------------ 状态与密钥
    def _state(self) -> dict:
        return read_verified_state(str(self.settings.state_path), self.state_mac_key)

    def _current_keys(self, state: dict) -> BrokerKeys:
        key_id = state["body"]["broker"].get("current_key_id") or ""
        if key_id:
            return self.keyring.load(key_id)
        ids = self.keyring.list_ids()
        if not ids:
            raise Unavailable("代理尚未初始化密钥")
        return self.keyring.load(ids[-1])

    def _keys_for_package(self, state: dict, package_id: str) -> BrokerKeys:
        package = state["body"]["packages"].get(package_id)
        if not isinstance(package, dict):
            raise NotFound("package 不存在")
        key_id = package.get("broker_key_id")
        if not isinstance(key_id, str):
            raise Unavailable("package 的代理密钥记录缺失")
        return self.keyring.load(key_id)

    def _identity_record(self, keys: BrokerKeys) -> dict:
        from ..protocol.identity import build_broker_identity

        ident = build_broker_identity(
            keys.key_id, keys.hpke_public, keys.signing_public, created_at=now()
        )
        return ident.record

    def _package_context(self, state: dict, package_id: str) -> _PackageContext:
        body = state["body"]
        package = body["packages"].get(package_id)
        if not isinstance(package, dict):
            raise NotFound("package 不存在")
        if package.get("status") != "active":
            raise ValidationError("package 已停用或撤销", code="package_inactive")
        if package_id in body.get("revoked_packages", {}):
            raise ValidationError("package 已撤销", code="package_revoked")
        sender_key_id = package.get("sender_key_id")
        entry = body["senders"].get(sender_key_id)
        if not isinstance(entry, dict):
            raise ValidationError("发送方身份未注册", code="sender_unknown")
        if entry.get("revoked"):
            raise ValidationError("发送方身份已撤销", code="sender_revoked")

        try:
            kc_bytes = read_keyconfig_bytes(self.settings, package_id)
            policy_bytes = read_policy_bytes(self.settings, package_id)
        except NotFound as exc:
            raise Unavailable("package 文件缺失") from exc
        if sha256_hex(kc_bytes) != package.get("keyconfig_sha256"):
            raise Conflict("KeyConfig 摘要与状态不一致", code="package_corrupt")
        if sha256_hex(policy_bytes) != package.get("policy_sha256"):
            raise Conflict("Policy 摘要与状态不一致", code="package_corrupt")

        import json

        try:
            keyconfig = json.loads(kc_bytes.decode("utf-8"))
            policy = json.loads(policy_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Conflict("package 元数据损坏", code="package_corrupt") from exc

        parsed_kc = verify_keyconfig(keyconfig)
        parsed_policy = verify_policy(policy)
        if parsed_kc.package_id != package_id or parsed_policy.package_id != package_id:
            raise Conflict("package_id 不一致", code="package_corrupt")
        if keyconfig.get("sender_key_id") != sender_key_id:
            raise Conflict("KeyConfig 发送方与状态不一致", code="package_corrupt")
        if keyconfig.get("sender_identity_hash") != package.get("sender_identity_hash"):
            raise Conflict("KeyConfig 身份摘要与状态不一致", code="package_corrupt")
        if keyconfig.get("sender_public_key") != entry.get("ed25519_public_key"):
            raise Conflict("KeyConfig 发送方公钥与注册记录不一致", code="package_corrupt")
        if policy.get("sender_key_id") != sender_key_id:
            raise Conflict("Policy 发送方与状态不一致", code="package_corrupt")
        if policy.get("sender_identity_hash") != package.get("sender_identity_hash"):
            raise Conflict("Policy 身份摘要与状态不一致", code="package_corrupt")
        if policy.get("sender_public_key") != entry.get("ed25519_public_key"):
            raise Conflict("Policy 发送方公钥与注册记录不一致", code="package_corrupt")
        if keyconfig.get("policy_hash") != policy_digest(policy):
            raise Conflict("KeyConfig 的 policy_hash 与 Policy 不一致", code="package_corrupt")
        if keyconfig.get("broker", {}).get("key_id") != package.get("broker_key_id"):
            raise Conflict("KeyConfig 的代理 key_id 与状态不一致", code="package_corrupt")

        keys = self.keyring.load(package["broker_key_id"])
        if keyconfig["broker"]["hpke_public_key"] != _b64(keys.hpke_public):
            raise Conflict("KeyConfig 的代理 HPKE 公钥与本地密钥不一致", code="package_corrupt")
        if keyconfig["broker"]["signing_public_key"] != _b64(keys.signing_public):
            raise Conflict("KeyConfig 的代理签名公钥与本地密钥不一致", code="package_corrupt")
        return _PackageContext(package, keyconfig, policy, entry, keys)

    # ------------------------------------------------------------ 操作
    def dispatch(self, op: str, body: dict, request_id: str, body_sha256: str) -> dict:
        if op == "health":
            return self.health()
        if op == "get_identity":
            return {"identity": self.get_identity()}
        if op == "create_grants":
            return self.create_grants(body)
        if op == "authorize":
            return self.authorize(body)
        if op == "deliver":
            return self.deliver(body)
        raise ValidationError("未知的代理操作", code="unknown_op")

    def health(self) -> dict:
        try:
            state = self._state()
            keys = self._current_keys(state)
            return {
                "status": "ok",
                "key_id": keys.key_id,
                "fingerprint": _fingerprint(keys.key_id, keys.hpke_public, keys.signing_public),
                "time": now(),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "degraded", "error": type(exc).__name__, "time": now()}

    def get_identity(self) -> dict:
        state = self._state()
        keys = self._current_keys(state)
        record = self._identity_record(keys)
        verify_broker_identity(record)
        return record

    # ------------------------------------------------------------ 发码
    def create_grants(self, body: dict) -> dict:
        allowed = {
            "batch_id",
            "package_id",
            "count",
            "uses_per_code",
            "expires_at",
            "policy_version",
        }
        if not isinstance(body, dict) or set(body.keys()) != allowed:
            raise ValidationError("create_grants 参数字段非法")
        batch_id = require_str(body.get("batch_id"), "batch_id", max_len=64)
        if not is_hex_id(batch_id, 16):
            raise ValidationError("batch_id 格式非法")
        package_id = require_str(body.get("package_id"), "package_id", max_len=32)
        if not is_hex_id(package_id, PKG_ID_BYTES):
            raise ValidationError("package_id 格式非法")
        count = require_int(body.get("count"), "count", 1, 10_000)
        uses = require_int(body.get("uses_per_code"), "uses_per_code", 1, 1_000_000)
        expires_at = require_int(body.get("expires_at"), "expires_at", 1)
        policy_version = require_int(body.get("policy_version"), "policy_version", 1)
        digest = sha256_hex(canonical_bytes(body))
        key = f"grants:{batch_id}"
        existing = self.idempotency.get(key)
        if isinstance(existing, dict):
            if existing.get("body_sha256") != digest:
                raise Conflict("同一 batch_id 携带了不同参数", code="batch_conflict")
            return existing["result"]

        state = self._state()
        ctx = self._package_context(state, package_id)
        if policy_version != ctx.policy.get("policy_version"):
            raise ValidationError("policy_version 不一致", code="policy_mismatch")
        grants = {
            gid: g for gid, g in state["body"]["grants"].items() if g.get("package_id") == package_id
        }
        check_new_grants(
            verify_policy(ctx.policy),
            grants,
            count=count,
            uses_per_code=uses,
            expires_at=expires_at,
        )
        sender_x = _b64_decode(ctx.identity_entry.get("x25519_public_key"), 32)
        package_bytes = bytes.fromhex(package_id)
        created = now()
        result_grants = []
        for _ in range(count):
            grant_id = new_hex_id(GRANT_ID_BYTES)
            plain_code = generate_code()
            try:
                verifier = code_verifier(plain_code, self.code_mac_key)
                sealed = _seal_code(plain_code, package_bytes, bytes.fromhex(grant_id), sender_x)
            finally:
                del plain_code
            result_grants.append(
                {
                    "grant_id": grant_id,
                    "code_verifier": verifier,
                    "sealed_code": sealed,
                    "expires_at": expires_at,
                    "max_uses": uses,
                    "policy_version": policy_version,
                    "batch_id": batch_id,
                    "created_at": created,
                }
            )
        result = {"batch_id": batch_id, "grants": result_grants}
        self.idempotency.put(key, {"body_sha256": digest, "result": result}, ttl=30 * 86400)
        self.audit("grants_created", package_id=package_id, count=count, batch_id=batch_id)
        return result

    # ------------------------------------------------------------ 预授权
    def authorize(self, body: dict) -> dict:
        if not isinstance(body, dict) or set(body.keys()) != {
            "outer",
            "state_generation",
            "state_digest",
        }:
            raise ValidationError("authorize 参数字段非法")
        state = self._state()
        generation = require_int(body.get("state_generation"), "state_generation", 0)
        digest = require_str(body.get("state_digest"), "state_digest", max_len=64)
        if state["generation"] != generation or envelope_digest(state) != digest:
            raise Conflict("状态快照已过期，请重试", code="state_changed")
        outer = body.get("outer")
        if not isinstance(outer, dict):
            raise ValidationError("authorize.outer 非法")
        package_id = require_str(outer.get("package_id"), "package_id", max_len=32)
        ctx = self._package_context(state, package_id)
        redeem = open_redeem_request(outer, ctx.keys.hpke_private)
        if redeem.package_id != package_id:
            raise ValidationError("兑换请求与 package 不一致", code="invalid_redeem")

        idem_key = f"authorize:{redeem.request_id}:{sha256_hex(canonical_bytes(body))}"
        cached = self.idempotency.get(idem_key)
        if isinstance(cached, dict):
            try:
                return {"ticket": verify_ticket(cached["ticket"], ctx.keys.signing_public)}
            except ValidationError:
                pass  # 过期或损坏：重新预授权

        grants = [
            g for g in state["body"]["grants"].values() if g.get("package_id") == package_id
        ]
        matched = None
        for grant in grants:
            try:
                validate_grant_record(grant)
            except ValidationError:
                continue
            if hmac.compare_digest(
                code_verifier(redeem.code, self.code_mac_key), grant["code_verifier"]
            ):
                matched = grant
                break
        if matched is None:
            self.audit("redeem_denied", package_id=package_id, reason="invalid_code")
            raise ValidationError("口令无效", code="invalid_code")
        policy = verify_policy(ctx.policy)
        if matched.get("policy_version") != policy.policy_version:
            raise ValidationError("授权版本与策略不一致", code="policy_mismatch")
        # 已提交的预留必须还能在票据过期后重新预授权；此时 used 可能已经
        # 等于 max_uses。只放行与预留完全匹配的同一 request_id，且仍拒绝撤销。
        reservation = state["body"]["requests"].get(redeem.request_id)
        reserved_match = (
            isinstance(reservation, dict)
            and reservation.get("status") == "RESERVED"
            and reservation.get("package_id") == package_id
            and reservation.get("grant_id") == matched["grant_id"]
            and reservation.get("recipient_pk_hash") == redeem.recipient_pk_hash
        )
        if reserved_match:
            if matched.get("revoked"):
                raise ValidationError("口令已撤销", code="grant_revoked")
        else:
            try:
                check_redemption(policy, matched, now=now())
            except ValidationError as exc:
                self.audit("redeem_denied", package_id=package_id, reason=exc.code)
                raise

        authorization_id = new_hex_id(16)
        issued = now()
        ticket = {
            "format": TICKET_FORMAT,
            "version": PROTOCOL_VERSION,
            "authorization_id": authorization_id,
            "grant_id": matched["grant_id"],
            "request_id": redeem.request_id,
            "recipient_pk_hash": redeem.recipient_pk_hash,
            "package_id": package_id,
            "policy_hash": policy.policy_hash,
            "state_generation": state["generation"],
            "state_digest": envelope_digest(state),
            "issued_at": issued,
            "expires_at": issued + TICKET_TTL,
            "broker_key_id": ctx.keys.key_id,
        }
        ticket = sign_object(
            Ed25519Keys.from_private(ctx.keys.signing_private), DOMAIN_AUTHORIZATION, ticket
        )
        self.idempotency.put(
            idem_key,
            {"ticket": ticket},
            ttl=TICKET_TTL * 4,
        )
        return {"ticket": ticket}

    # ------------------------------------------------------------ 交付
    def deliver(self, body: dict) -> dict:
        if not isinstance(body, dict) or set(body.keys()) != {
            "outer",
            "ticket",
            "reservation_id",
        }:
            raise ValidationError("deliver 参数字段非法")
        reservation_id = require_str(body.get("reservation_id"), "reservation_id", max_len=64)
        if not is_hex_id(reservation_id, 16):
            raise ValidationError("reservation_id 格式非法")
        state = self._state()
        outer = body.get("outer")
        if not isinstance(outer, dict):
            raise ValidationError("deliver.outer 非法")
        package_id = require_str(outer.get("package_id"), "package_id", max_len=32)
        ctx = self._package_context(state, package_id)
        redeem = open_redeem_request(outer, ctx.keys.hpke_private)
        request_digest = sha256_hex(canonical_bytes(outer))

        ticket = body.get("ticket")
        if not isinstance(ticket, dict):
            raise ValidationError("票据必须是 JSON 对象", code="bad_ticket")
        if ticket.get("broker_key_id") != ctx.keys.key_id:
            raise ValidationError("票据的代理 key_id 与 package 不一致", code="bad_ticket")
        verify_ticket(ticket, ctx.keys.signing_public)
        if ticket.get("request_id") != redeem.request_id:
            raise ValidationError("票据 request_id 不匹配", code="bad_ticket")
        if ticket.get("package_id") != package_id:
            raise ValidationError("票据 package_id 不匹配", code="bad_ticket")
        if ticket.get("recipient_pk_hash") != redeem.recipient_pk_hash:
            raise ValidationError("票据接收方摘要不匹配", code="bad_ticket")

        grant = state["body"]["grants"].get(ticket["grant_id"])
        if not isinstance(grant, dict):
            raise ValidationError("授权不存在", code="grant_unknown")
        validate_grant_record(grant)
        if grant.get("package_id") != package_id:
            raise ValidationError("票据授权不属于该 package", code="grant_mismatch")
        request_record = state["body"]["requests"].get(redeem.request_id)
        if not isinstance(request_record, dict):
            raise ValidationError("服务端预留记录不存在", code="reservation_missing")
        if request_record.get("status") != "RESERVED":
            raise ValidationError("预留记录状态不是 RESERVED", code="reservation_invalid")
        for field, expected in (
            ("package_id", package_id),
            ("grant_id", ticket["grant_id"]),
            ("recipient_pk_hash", ticket["recipient_pk_hash"]),
            ("authorization_id", ticket["authorization_id"]),
            ("reservation_id", reservation_id),
        ):
            if request_record.get(field) != expected:
                raise ValidationError(
                    f"预留记录 {field} 与票据不一致", code="reservation_invalid"
                )
        if int(grant.get("used", 0)) < 1:
            raise ValidationError("预留未计入已消费次数", code="reservation_invalid")

        policy = verify_policy(ctx.policy)
        if ticket.get("policy_hash") != policy.policy_hash:
            raise ValidationError("票据策略摘要不匹配", code="policy_mismatch")

        cached = self.cache.get(redeem.request_id, request_digest)
        if cached is not None:
            self.audit("redeem_delivered", package_id=package_id, request_id=redeem.request_id, cached=True)
            return {"envelope": cached, "request_digest": request_digest}

        k_pkg = open_package_key(
            verify_keyconfig(ctx.keyconfig), ctx.keys.hpke_private
        )
        try:
            core = make_envelope_core(
                k_pkg=bytes(k_pkg),
                package_id=package_id,
                grant_id=ticket["grant_id"],
                request_id=redeem.request_id,
                recipient_public_key=redeem.recipient_public_key,
                config_version=int(ctx.keyconfig.get("version", 1)),
                broker_key_id=ctx.keys.key_id,
            )
            envelope = make_envelope(
                core=core,
                broker_signing_private=ctx.keys.signing_private,
                issued_at=now(),
            ).to_dict()
        finally:
            wipe(k_pkg)
        self.cache.put(redeem.request_id, request_digest, envelope)
        self.audit("redeem_delivered", package_id=package_id, request_id=redeem.request_id)
        return {"envelope": envelope, "request_digest": request_digest}


def _b64(raw: bytes) -> str:
    from ..util.canonical import b64u_encode

    return b64u_encode(raw)


def _b64_decode(value, expected_len: int) -> bytes:
    from ..util.canonical import b64u_decode

    try:
        return b64u_decode(value, expected_len=expected_len)
    except (TypeError, ValueError) as exc:
        raise ValidationError("发送方 X25519 公钥非法") from exc


def _seal_code(code: str, package_id: bytes, grant_id: bytes, sender_x: bytes) -> dict:
    from ..protocol.identity import seal_code

    return seal_code(code, package_id, grant_id, sender_x)


def _fingerprint(key_id: str, hpke_pub: bytes, sign_pub: bytes) -> str:
    from ..crypto.keys import broker_fingerprint
    from ..util.canonical import b64u_encode

    return broker_fingerprint(key_id, b64u_encode(hpke_pub), b64u_encode(sign_pub))
