"""Bearer 认证的 JSON API。

安全约定：
* 只认 ``Authorization: Bearer``，即使请求带 Cookie 也不认；
* token 绑定状态中的 ``auth.api_epoch``，重新认证纪元后旧 token 全部失效；
* 不返回 ``code_mac_key``、``K_pkg``、任何私钥；口令只以发送方公钥密封后的
  ``sealed_code`` 形式离开代理。

上传走流式临时文件，先校验声明的大小与 SHA-256，再原子改名为 ``payload.vspk``。
"""

from __future__ import annotations

import functools
import hashlib
import os
from typing import Callable

from flask import Blueprint, g, jsonify, request

from ..errors import (
    Conflict,
    Forbidden,
    IpcError,
    NotAuthenticated,
    NotFound,
    Unavailable,
    ValidationError,
)
from ..protocol.grants import make_grant, validate_grant_record
from ..protocol.identity import (
    build_broker_identity,
    check_sender_fields,
    verify_broker_identity,
    verify_sender_identity,
)
from ..protocol.keyconfig import keyconfig_digest, verify_keyconfig
from ..protocol.policy import (
    check_new_grants,
    grant_metrics,
    policy_digest,
    verify_policy,
)
from ..storage.package_store import (
    commit_payload,
    create_package_dir,
    delete_package_dir,
    upload_temp_path,
    write_meta,
)
from ..util.canonical import b64u_decode
from ..util.ids import GRANT_ID_BYTES, PKG_ID_BYTES, is_hex_id, new_hex_id
from ..util.timeutil import now, parse_duration
from ..version import __version__
from .app import get_context
from .auth import issue_bearer, verify_bearer
from .login import authenticate
from .package_checks import load_package_context
from .redeem_flow import redeem

bp = Blueprint("api", __name__, url_prefix="/api/v1")

MAX_BATCH = 10_000
_SHA256_HEX = set("0123456789abcdef")


# ------------------------------------------------------------------ 工具
def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("请求体必须是 JSON 对象")
    return data


def _str_field(data: dict, name: str, *, max_len: int = 512) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValidationError(f"字段 {name} 非法")
    return value


def _epoch(context) -> int:
    if context.store.degraded:
        raise Unavailable("状态处于降级模式", code="state_corrupt")
    return int(context.store.snapshot()["body"]["auth"].get("api_epoch", 1))


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def require_bearer(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        context = get_context()
        if request.cookies.get("vaultshare_session"):
            # 显式拒绝：避免浏览器把 API 当 Cookie 会话用，绕过 CSRF 模型。
            raise Forbidden("API 不接受 Cookie 认证，请使用 Bearer token", code="cookie_auth")
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise NotAuthenticated("缺少 Bearer token", code="bearer_required")
        token = header[len("Bearer ") :].strip()
        g.api_user = verify_bearer(context.secret, token, _epoch(context))
        return fn(*args, **kwargs)

    return wrapper


def _load_ctx(context, package_id: str, *, require_active: bool = True, require_payload: bool = False):
    snapshot = context.store.snapshot()
    return snapshot, load_package_context(
        context.settings,
        snapshot["body"],
        package_id,
        require_active=require_active,
        require_payload=require_payload,
    )


def _broker_identity(context, key_id: str | None = None) -> dict:
    try:
        record = context.broker.call("get_identity", {})["identity"]
    except IpcError as exc:
        context.audit("broker_unavailable", op="get_identity", code=exc.code)
        raise Unavailable("密钥代理暂不可用", code="broker_unavailable") from exc
    ident = verify_broker_identity(record)
    if key_id is not None and ident.key_id != key_id:
        raise Conflict("代理当前密钥与 KeyConfig 不一致", code="broker_key_changed")
    return ident.record


# ------------------------------------------------------------------ 公开
@bp.get("/health")
def health():
    context = get_context()
    broker = {"status": "unavailable"}
    try:
        broker = context.broker.call("health", {})
    except Exception as exc:  # noqa: BLE001 - 健康检查本身不能抛
        broker = {"status": "unavailable", "error": type(exc).__name__}
    return jsonify(
        {
            "ok": True,
            "version": __version__,
            "time": now(),
            "state": {
                "degraded": context.store.degraded,
                "reason": context.store.degraded_reason,
            },
            "broker": broker,
        }
    )


@bp.post("/login")
def login():
    context = get_context()
    if not context.login_window.allow(_client_ip()):
        raise Forbidden("尝试过于频繁，请稍后再试", code="rate_limited")
    data = _body()
    username = authenticate(
        context,
        data.get("username", ""),
        data.get("password", ""),
        data.get("totp", ""),
        _client_ip(),
    )
    token, expires = issue_bearer(context.secret, username, _epoch(context))
    return jsonify({"token": token, "expires": expires, "username": username})


@bp.post("/redeem")
def redeem_endpoint():
    context = get_context()
    if not context.redeem_window.allow(_client_ip()):
        raise Forbidden("兑换请求过于频繁，请稍后再试", code="rate_limited")
    outer = _body()
    outcome = redeem(context, outer)
    context.audit(
        "redeem_delivered",
        package_id=outer.get("package_id"),
        request_id=outcome.request_id,
        replayed=outcome.replayed,
    )
    return jsonify(
        {
            "request_id": outcome.request_id,
            "envelope": outcome.envelope,
            "replayed": outcome.replayed,
        }
    )


# ------------------------------------------------------------------ 身份
@bp.post("/identity")
@require_bearer
def register_identity():
    context = get_context()
    identity = verify_sender_identity(_body())

    def mutate(body: dict) -> dict:
        senders = body.setdefault("senders", {})
        existing = senders.get(identity.sender_key_id)
        if isinstance(existing, dict):
            if existing.get("revoked"):
                raise Conflict("该发送方身份已撤销", code="sender_revoked")
            if existing.get("identity_hash") != identity.digest:
                raise Conflict(
                    "同一 sender_key_id 的身份内容不同，拒绝静默覆盖",
                    code="identity_conflict",
                )
            return _sender_summary(existing)
        senders[identity.sender_key_id] = {
            "sender_key_id": identity.sender_key_id,
            "identity_hash": identity.digest,
            "ed25519_public_key": identity.record["ed25519_public_key"],
            "x25519_public_key": identity.record["x25519_public_key"],
            "registered_at": now(),
            "revoked": False,
            "record": dict(identity.record),
        }
        return _sender_summary(senders[identity.sender_key_id])

    summary = context.store.transaction(mutate)
    context.audit(
        "identity_registered", sender_key_id=identity.sender_key_id, by=g.api_user
    )
    return jsonify({"identity": summary})


def _sender_summary(entry: dict) -> dict:
    return {
        "sender_key_id": entry.get("sender_key_id"),
        "identity_hash": entry.get("identity_hash"),
        "ed25519_public_key": entry.get("ed25519_public_key"),
        "x25519_public_key": entry.get("x25519_public_key"),
        "registered_at": entry.get("registered_at"),
        "revoked": bool(entry.get("revoked")),
    }


@bp.get("/broker")
def broker_info():
    # 代理公钥与指纹是公开材料；真实性来自带外核对，而不是本响应。
    # 不做登录要求，发送方才能在创建第一个包之前取得它。
    context = get_context()
    return jsonify({"identity": _broker_identity(context)})


# ------------------------------------------------------------------ 包
@bp.post("/packages")
@require_bearer
def create_package():
    context = get_context()
    data = _body()
    keyconfig = data.get("keyconfig")
    policy = data.get("policy")
    if not isinstance(keyconfig, dict) or not isinstance(policy, dict):
        raise ValidationError("keyconfig / policy 必须是 JSON 对象")

    payload_mode = data.get("payload_mode", "server")
    if payload_mode not in ("server", "local"):
        raise ValidationError("payload_mode 只能是 server 或 local")

    parsed_kc = verify_keyconfig(keyconfig)
    parsed_policy = verify_policy(policy)
    package_id = parsed_kc.package_id
    if parsed_policy.package_id != package_id:
        raise ValidationError("KeyConfig 与 Policy 的 package_id 不一致")
    if keyconfig.get("policy_hash") != policy_digest(policy):
        raise ValidationError("KeyConfig 的 policy_hash 与 Policy 不一致")
    for field in ("sender_key_id", "sender_identity_hash", "sender_public_key"):
        if keyconfig.get(field) != policy.get(field):
            raise ValidationError(f"KeyConfig 与 Policy 的 {field} 不一致")

    live = _broker_identity(context)
    if live["key_id"] != keyconfig["broker"]["key_id"]:
        raise Conflict("打包时使用的代理密钥已不是当前密钥", code="broker_key_changed")
    if live["hpke_public_key"] != keyconfig["broker"]["hpke_public_key"]:
        raise Conflict("KeyConfig 中的代理 HPKE 公钥与代理不一致", code="broker_mismatch")
    if live["signing_public_key"] != keyconfig["broker"]["signing_public_key"]:
        raise Conflict("KeyConfig 中的代理签名公钥与代理不一致", code="broker_mismatch")

    kc_bytes_digest = keyconfig_digest(keyconfig)
    policy_bytes_digest = policy_digest(policy)

    def check_sender(body: dict) -> dict:
        entry = body.get("senders", {}).get(keyconfig["sender_key_id"])
        if not isinstance(entry, dict):
            raise ValidationError("发送方身份未注册", code="sender_unknown")
        if entry.get("revoked"):
            raise Forbidden("发送方身份已撤销", code="sender_revoked")
        check_sender_fields(keyconfig, entry, "KeyConfig")
        check_sender_fields(policy, entry, "Policy")
        return entry

    snapshot = context.store.snapshot()
    check_sender(snapshot["body"])
    if package_id in snapshot["body"].get("packages", {}):
        raise Conflict("package 已存在", code="package_exists")

    created_dir = create_package_dir(context.settings, package_id, keyconfig, policy)
    try:

        def mutate(body: dict) -> None:
            if package_id in body.get("packages", {}):
                raise Conflict("package 已存在", code="package_exists")
            entry = check_sender(body)
            body.setdefault("packages", {})[package_id] = {
                "status": "active",
                "created_at": now(),
                "keyconfig_sha256": kc_bytes_digest,
                "policy_sha256": policy_bytes_digest,
                "payload_sha256": "",
                "payload_size": 0,
                "payload_mode": payload_mode,
                "broker_key_id": keyconfig["broker"]["key_id"],
                "sender_key_id": entry["sender_key_id"],
                "sender_identity_hash": entry["identity_hash"],
            }
            body.setdefault("grants_counters", {})[package_id] = {
                "issued": 0,
                "allocated_uses": 0,
                "used": 0,
            }

        context.store.transaction(mutate)
    except BaseException:
        delete_package_dir(context.settings, package_id)
        raise

    context.audit(
        "package_created",
        package_id=package_id,
        sender_key_id=keyconfig["sender_key_id"],
        broker_key_id=keyconfig["broker"]["key_id"],
        payload_mode=payload_mode,
        by=g.api_user,
    )
    return jsonify(
        {"package_id": package_id, "status": "created", "payload_mode": payload_mode}
    ), 201


@bp.put("/packages/<package_id>/blob")
@require_bearer
def upload_blob(package_id: str):
    context = get_context()
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    declared_digest = (request.headers.get("X-VaultShare-SHA256") or "").strip().lower()
    declared_size_raw = (request.headers.get("X-VaultShare-Size") or "").strip()
    if len(declared_digest) != 64 or not set(declared_digest) <= _SHA256_HEX:
        raise ValidationError("缺少或非法的 X-VaultShare-SHA256")
    try:
        declared_size = int(declared_size_raw)
    except ValueError as exc:
        raise ValidationError("缺少或非法的 X-VaultShare-Size") from exc
    if declared_size <= 0 or declared_size > context.settings.upload_max_bytes:
        raise ValidationError("文件大小超出允许范围")

    snapshot, pkg = _load_ctx(context, package_id)
    if pkg.package.get("payload_mode", "server") == "local":
        raise Conflict(
            "该包声明为本地交付，服务器不接收密文",
            code="local_payload",
        )
    if pkg.package.get("payload_sha256"):
        raise Conflict("该包已上传过文件，拒绝覆盖", code="payload_exists")

    tmp = upload_temp_path(context.settings, package_id)
    digest = hashlib.sha256()
    written = 0
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = request.stream.read(context.settings.upload_chunk_bytes)
                if not chunk:
                    break
                written += len(chunk)
                if written > declared_size or written > context.settings.upload_max_bytes:
                    raise ValidationError("上传内容超过声明大小")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if written != declared_size:
            raise ValidationError("上传大小与声明不一致")
        if digest.hexdigest() != declared_digest:
            raise ValidationError("上传 SHA-256 与声明不一致")
        commit_payload(context.settings, package_id, tmp, declared_digest, declared_size)
    except BaseException:
        if tmp.exists():
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise

    write_meta(
        context.settings,
        package_id,
        {
            "package_id": package_id,
            "payload_size": declared_size,
            "payload_sha256": declared_digest,
            "uploaded_at": now(),
        },
    )

    def mutate(body: dict) -> None:
        record = body.get("packages", {}).get(package_id)
        if not isinstance(record, dict):
            raise NotFound("package 不存在")
        if record.get("payload_sha256"):
            if record.get("payload_sha256") == declared_digest:
                return
            raise Conflict("该包已上传过文件，拒绝覆盖", code="payload_exists")
        record["payload_sha256"] = declared_digest
        record["payload_size"] = declared_size

    context.store.transaction(mutate)
    context.audit(
        "payload_uploaded",
        package_id=package_id,
        size=declared_size,
        sha256=declared_digest,
        by=g.api_user,
    )
    return jsonify({"package_id": package_id, "size": declared_size, "sha256": declared_digest})


def _resolve_expiry(policy, data: dict) -> int:
    current = now()
    if "expires_at" in data:
        value = data["expires_at"]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError("expires_at 必须是整数时间戳")
        expires_at = value
    elif "expires_in" in data:
        try:
            expires_at = current + parse_duration(str(data["expires_in"]))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
    else:
        raise ValidationError("必须提供 expires_at 或 expires_in")
    if expires_at <= current:
        raise ValidationError("过期时间必须晚于当前时间")
    if expires_at > policy.latest_expiry:
        raise ValidationError("过期时间超过策略上限", code="quota_denied")
    return expires_at


@bp.post("/packages/<package_id>/grants")
@require_bearer
def create_grants(package_id: str):
    context = get_context()
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    data = _body()
    count = data.get("count", 1)
    uses = data.get("uses_per_code", 1)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_BATCH:
        raise ValidationError("count 必须是 1..10000 的整数")
    if not isinstance(uses, int) or isinstance(uses, bool) or uses < 1:
        raise ValidationError("uses_per_code 必须是正整数")
    batch_id = data.get("batch_id") or new_hex_id(16)
    if not is_hex_id(batch_id, 16):
        raise ValidationError("batch_id 格式非法")

    snapshot, pkg = _load_ctx(context, package_id, require_active=True, require_payload=True)
    policy = pkg.policy_parsed
    expires_at = _resolve_expiry(policy, data)
    if uses > policy.max_uses_per_code:
        raise ValidationError("uses_per_code 超过策略允许值", code="quota_denied")

    # 预检：早失败，避免无意义地让代理生成口令。权威校验仍在事务里。
    check_new_grants(
        policy,
        snapshot["body"]["grants"],
        count=count,
        uses_per_code=uses,
        expires_at=expires_at,
    )

    try:
        result = context.broker.call(
            "create_grants",
            {
                "batch_id": batch_id,
                "package_id": package_id,
                "count": count,
                "uses_per_code": uses,
                "expires_at": expires_at,
                "policy_version": policy.policy_version,
            },
        )
    except IpcError as exc:
        context.audit("broker_unavailable", op="create_grants", code=exc.code)
        if exc.code in ("quota_denied", "policy_mismatch", "invalid"):
            raise ValidationError(exc.message, code=exc.code) from exc
        raise Unavailable("密钥代理暂不可用", code="broker_unavailable") from exc

    broker_grants = result.get("grants")
    if not isinstance(broker_grants, list) or not broker_grants:
        raise Unavailable("密钥代理返回的授权列表非法", code="broker_error")

    def mutate(body: dict) -> dict:
        # 幂等：同一 batch 已经落盘则直接返回现状。
        already = [
            gid
            for gid, grant in body.get("grants", {}).items()
            if isinstance(grant, dict) and grant.get("batch_id") == batch_id
        ]
        if already:
            return {"created": [], "existing": sorted(already)}

        live_ctx = load_package_context(
            context.settings,
            body,
            package_id,
            require_active=True,
            require_payload=True,
        )
        live_policy = live_ctx.policy_parsed
        if live_policy.policy_hash != policy.policy_hash:
            raise Conflict("策略在创建过程中发生变化", code="policy_changed")
        check_new_grants(
            live_policy,
            body.get("grants", {}),
            count=count,
            uses_per_code=uses,
            expires_at=expires_at,
        )
        created = []
        for item in broker_grants:
            if not isinstance(item, dict):
                raise Unavailable("代理返回的授权项非法", code="broker_error")
            record = make_grant(
                grant_id=item.get("grant_id"),
                package_id=package_id,
                code_verifier_hex=item.get("code_verifier"),
                sealed_code=item.get("sealed_code"),
                expires_at=item.get("expires_at"),
                max_uses=item.get("max_uses"),
                policy_version=item.get("policy_version"),
                batch_id=item.get("batch_id"),
                created_at=item.get("created_at"),
            )
            validate_grant_record(record)
            if record["grant_id"] in body["grants"]:
                raise Conflict("代理返回了重复的 grant_id", code="grant_conflict")
            if record["batch_id"] != batch_id or record["package_id"] != package_id:
                raise Unavailable("代理返回的授权与请求不一致", code="broker_error")
            if record["max_uses"] != uses or record["expires_at"] != expires_at:
                raise Unavailable("代理返回的授权参数与请求不一致", code="broker_error")
            body["grants"][record["grant_id"]] = record
            created.append(record["grant_id"])
        body.setdefault("grants_counters", {})[package_id] = grant_metrics(
            body["grants"], package_id
        )
        return {"created": created, "existing": []}

    outcome = context.store.transaction(mutate)
    context.audit(
        "grants_created",
        package_id=package_id,
        batch_id=batch_id,
        count=len(outcome["created"]),
        by=g.api_user,
    )
    grants = []
    for gid in outcome["created"] or outcome["existing"]:
        grant = context.store.snapshot()["body"]["grants"].get(gid)
        if isinstance(grant, dict):
            grants.append(_grant_meta(grant))
    return jsonify({"batch_id": batch_id, "grants": grants})


def _grant_meta(grant: dict) -> dict:
    return {
        "grant_id": grant.get("grant_id"),
        "package_id": grant.get("package_id"),
        "expires_at": grant.get("expires_at"),
        "max_uses": grant.get("max_uses"),
        "used": grant.get("used"),
        "revoked": bool(grant.get("revoked")),
        "batch_id": grant.get("batch_id"),
        "created_at": grant.get("created_at"),
    }


@bp.get("/packages/<package_id>/codes")
@require_bearer
def list_codes(package_id: str):
    """返回密封口令。只有持有发送方 X25519 私钥的人能解开。"""
    context = get_context()
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    snapshot, pkg = _load_ctx(context, package_id, require_active=False)
    grants = []
    for grant in snapshot["body"].get("grants", {}).values():
        if not isinstance(grant, dict) or grant.get("package_id") != package_id:
            continue
        meta = _grant_meta(grant)
        meta["sealed_code"] = grant.get("sealed_code")
        grants.append(meta)
    grants.sort(key=lambda item: int(item.get("created_at") or 0))
    context.audit(
        "codes_read", package_id=package_id, count=len(grants), by=g.api_user
    )
    return jsonify({"package_id": package_id, "grants": grants})


@bp.get("/packages/<package_id>/public")
def public_package(package_id: str):
    """公开材料：接收方自行验签并核对 TOFU 指纹，不能只信本响应。"""
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    context = get_context()
    snapshot, pkg = _load_ctx(context, package_id, require_active=False)
    entry = snapshot["body"].get("senders", {}).get(pkg.package.get("sender_key_id"))
    if not isinstance(entry, dict) or not isinstance(entry.get("record"), dict):
        raise Conflict("发送方身份记录不完整，请重新注册身份", code="identity_missing")
    broker = pkg.keyconfig["broker"]
    broker_identity = build_broker_identity(
        broker["key_id"],
        b64u_decode(broker["hpke_public_key"], expected_len=32),
        b64u_decode(broker["signing_public_key"], expected_len=32),
        created_at=int(pkg.keyconfig.get("created_at", 0)),
    )
    return jsonify(
        {
            "package_id": package_id,
            "keyconfig": pkg.keyconfig,
            "policy": pkg.policy,
            "sender_identity": entry["record"],
            "broker_identity": broker_identity.record,
            "payload_size": int(pkg.package.get("payload_size") or 0),
            "payload_sha256": pkg.package.get("payload_sha256") or "",
            "payload_mode": pkg.package.get("payload_mode", "server"),
            "status": pkg.package.get("status"),
        }
    )


@bp.get("/packages/<package_id>/blob")
def download_blob(package_id: str):
    """下载加密容器。内容是密文，公开下载不会泄露明文。"""
    from flask import send_file

    from ..storage.package_store import payload_path

    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    context = get_context()
    snapshot, pkg = _load_ctx(context, package_id, require_active=False)
    if pkg.package.get("payload_mode", "server") == "local":
        raise NotFound(
            "该包为本地交付，服务器不保存密文", code="local_payload"
        )
    expected = pkg.package.get("payload_sha256")
    if not expected:
        raise NotFound("该包尚未上传文件", code="payload_missing")
    path = payload_path(context.settings, package_id)
    if not path.is_file():
        raise Conflict("共享包文件缺失", code="payload_missing")
    return send_file(
        str(path),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name="payload.vspk",
        conditional=True,
    )


# ------------------------------------------------------------------ 撤销
def _revoke_package(context, package_id: str, actor: str) -> None:
    def mutate(body: dict) -> None:
        record = body.get("packages", {}).get(package_id)
        if not isinstance(record, dict):
            raise NotFound("package 不存在")
        body.setdefault("revoked_packages", {})[package_id] = now()
        record["status"] = "revoked"
        for grant in body.get("grants", {}).values():
            if isinstance(grant, dict) and grant.get("package_id") == package_id:
                grant["revoked"] = True

    context.store.transaction(mutate)
    context.audit("package_revoked", package_id=package_id, by=actor)


@bp.post("/packages/<package_id>/revoke")
@require_bearer
def revoke_package(package_id: str):
    context = get_context()
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    _revoke_package(context, package_id, g.api_user)
    return jsonify({"package_id": package_id, "status": "revoked"})


@bp.post("/grants/<grant_id>/revoke")
@require_bearer
def revoke_grant(grant_id: str):
    context = get_context()
    if not is_hex_id(grant_id, GRANT_ID_BYTES):
        raise ValidationError("grant_id 格式非法")

    def mutate(body: dict) -> None:
        grant = body.get("grants", {}).get(grant_id)
        if not isinstance(grant, dict):
            raise NotFound("授权不存在")
        grant["revoked"] = True

    context.store.transaction(mutate)
    context.audit("grant_revoked", grant_id=grant_id, by=g.api_user)
    return jsonify({"grant_id": grant_id, "revoked": True})
