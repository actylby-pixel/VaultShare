"""中文网页：登录、概览、包列表/详情、发送方、审核日志、系统与撤销。

默认情况下网页只做管理与查看：上传、发码、兑换走 CLI/API。显式设置
``VAULTSHARE_WEB_UPLOAD=1`` 后才会出现网页上传（见 ``web_upload`` 模块），
这条路径会短暂接触发送方私钥与 ``K_pkg``。所有页面都不含 JavaScript
（CSP 为 ``script-src 'none'``）。
"""

from __future__ import annotations

import json
import os
import secrets

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..errors import NotAuthenticated, ValidationError, VaultShareError
from ..protocol.policy import grant_metrics
from ..storage.notes import normalize_note
from ..util.timeutil import format_iso, now
from .app import get_context
from .login import authenticate
from .package_checks import load_package_context
from .ratelimit import check_csrf
from .web_upload import run_web_add_grants, run_web_upload

bp = Blueprint("web", __name__)

_MAX_FORM = 8 * 1024


def _safe_next(target: str | None) -> str:
    if not target or not target.startswith("/") or target.startswith("//"):
        return url_for("web.index")
    if "\\" in target or "\x00" in target:
        return url_for("web.index")
    return target


def _initial_credentials_pending() -> bool:
    return get_context().settings.initial_credentials_path.exists()


def _csrf_failure_message() -> str:
    """区分“浏览器没带 Cookie”和“页面确实过期”，否则用户无从排查。"""
    cookie_name = current_app.config["SESSION_COOKIE_NAME"]
    if request.cookies.get(cookie_name) is None:
        return (
            "浏览器没有发送会话 Cookie，登录请求无法通过校验。"
            "请确认访问地址与启动信息一致：直接启动时用 http://127.0.0.1:5000；"
            "只有设置 VAULTSHARE_HTTPS=1（TLS 由反向代理终结）时才用 https://。"
            "同时请允许本站 Cookie，且不要在页面打开后重启服务。"
        )
    return "页面已过期，请重新提交"


@bp.route("/login", methods=["GET", "POST"])
def login():
    context = get_context()
    pre_csrf = session.get("pre_csrf")
    if not pre_csrf:
        pre_csrf = secrets.token_urlsafe(32)
        session["pre_csrf"] = pre_csrf

    error = ""
    next_target = _safe_next(request.values.get("next"))

    if request.method == "POST":
        try:
            check_csrf(pre_csrf, request.form.get("csrf_token"))
        except ValidationError:
            error = _csrf_failure_message()
            # 立即换发新 token：这次失败可能是旧页面/旧 Cookie 造成的，
            # 重新渲染的表单要能直接再提交一次。
            session["pre_csrf"] = secrets.token_urlsafe(32)
            cookie_name = current_app.config["SESSION_COOKIE_NAME"]
            current_app.logger.warning(
                "login CSRF failed: cookie=%s ip=%s",
                "present" if request.cookies.get(cookie_name) else "missing",
                request.remote_addr,
            )
        else:
            try:
                if not context.login_window.allow(request.remote_addr or "unknown"):
                    error = "登录尝试过于频繁，请稍后再试"
                else:
                    username = request.form.get("username", "")
                    password = request.form.get("password", "")
                    totp_code = request.form.get("totp", "")
                    authenticate(
                        context,
                        username,
                        password,
                        totp_code,
                        request.remote_addr or "unknown",
                    )
            except NotAuthenticated as exc:
                error = exc.message
            else:
                # 会话固定防护：登录成功丢弃旧会话，发放全新 sid。
                context.sessions.destroy(session.get("sid"))
                fresh = context.sessions.create(username)
                session.clear()
                session.permanent = True
                session["sid"] = fresh.sid
                context.audit("login_session", username=username, ip=request.remote_addr)
                return redirect(next_target)

    return (
        render_template(
            "login.html",
            error=error,
            next_target=next_target,
            initial_pending=_initial_credentials_pending(),
        ),
        200 if not error else 401,
    )


@bp.post("/logout")
def logout():
    context = get_context()
    context.sessions.destroy(session.get("sid"))
    context.audit("logout", ip=request.remote_addr)
    session.clear()
    return redirect(url_for("web.login"))


def _notes() -> dict:
    context = get_context()
    if context.notes is None:
        return {"packages": {}, "grants": {}}
    return context.notes.snapshot()


def _package_views(body: dict, notes: dict | None = None) -> list[dict]:
    rows = []
    packages = body.get("packages", {})
    package_notes = (notes or {}).get("packages", {})
    for package_id in sorted(packages):
        package = packages[package_id]
        if not isinstance(package, dict):
            continue
        metrics = grant_metrics(body.get("grants", {}), package_id)
        rows.append(
            {
                "package_id": package_id,
                "note": package_notes.get(package_id, ""),
                "status": package.get("status", "unknown"),
                "created_at": package.get("created_at", 0),
                "created_text": format_iso(package.get("created_at", 0)),
                "sender_key_id": package.get("sender_key_id", ""),
                "broker_key_id": package.get("broker_key_id", ""),
                "has_payload": bool(package.get("payload_sha256")),
                "payload_mode": package.get("payload_mode", "server"),
                "issued": metrics["issued"],
                "allocated_uses": metrics["allocated_uses"],
                "used": metrics["used"],
            }
        )
    return rows


def _audit_tail(limit: int = 200) -> list[dict]:
    """读取审计日志末尾若干条；只读，不修改文件。"""
    path = get_context().settings.audit_path
    chunk = 1024 * 1024
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - chunk)
            f.seek(start)
            raw = f.read()
    except OSError:
        return []
    lines = raw.splitlines()
    if start > 0 and lines:
        lines = lines[1:]  # 第一行可能被截断
    events = []
    for line in lines[-limit:]:
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        record["ts_text"] = format_iso(int(record.get("ts") or 0))
        events.append(record)
    events.reverse()
    return events


def _broker_status(context) -> dict:
    try:
        return context.broker.call("health", {})
    except Exception as exc:  # noqa: BLE001 - 面板只展示状态，不阻断页面
        return {"status": "unavailable", "error": type(exc).__name__}


@bp.get("/")
def index():
    context = get_context()
    state = context.store.display_state()
    body = state.get("body") or {}
    rows = _package_views(body, _notes())
    grants = [g for g in (body.get("grants") or {}).values() if isinstance(g, dict)]
    senders = [s for s in (body.get("senders") or {}).values() if isinstance(s, dict)]
    summary = {
        "packages_total": len(rows),
        "packages_active": sum(1 for row in rows if row["status"] == "active"),
        # 本地交付的包本来就没有服务器端密文，不算“待上传”。
        "packages_pending": sum(
            1
            for row in rows
            if not row["has_payload"] and row["payload_mode"] != "local"
        ),
        "senders_total": len(senders),
        "senders_revoked": sum(1 for s in senders if s.get("revoked")),
        "grants_total": len(grants),
        "grants_active": sum(
            1
            for g in grants
            if not g.get("revoked") and int(g.get("expires_at", 0)) > now()
        ),
        "allocated_uses": sum(int(g.get("max_uses", 0)) for g in grants),
        "used": sum(int(g.get("used", 0)) for g in grants),
    }
    return render_template(
        "index.html",
        state=state,
        summary=summary,
        packages=rows[:8],
        events=_audit_tail(8),
        broker_health=_broker_status(context),
        initial_pending=_initial_credentials_pending(),
    )


@bp.get("/packages")
def packages():
    context = get_context()
    state = context.store.display_state()
    body = state.get("body") or {}
    return render_template(
        "packages.html",
        state=state,
        packages=_package_views(body, _notes()),
        initial_pending=_initial_credentials_pending(),
        broker_health=_broker_status(context),
    )


@bp.get("/senders")
def senders():
    context = get_context()
    state = context.store.display_state()
    body = state.get("body") or {}
    package_owner: dict[str, int] = {}
    for package in (body.get("packages") or {}).values():
        if isinstance(package, dict):
            key = package.get("sender_key_id") or ""
            package_owner[key] = package_owner.get(key, 0) + 1
    rows = []
    for key_id, entry in sorted((body.get("senders") or {}).items()):
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "sender_key_id": key_id,
                "identity_hash": entry.get("identity_hash", ""),
                "registered_text": format_iso(int(entry.get("registered_at") or 0)),
                "revoked": bool(entry.get("revoked")),
                "package_count": package_owner.get(key_id, 0),
                "ed25519_public_key": entry.get("ed25519_public_key", ""),
                "x25519_public_key": entry.get("x25519_public_key", ""),
            }
        )
    return render_template("senders.html", state=state, senders=rows)


@bp.get("/audit")
def audit():
    context = get_context()
    try:
        limit = int(request.args.get("limit", "200"))
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 2000))
    return render_template(
        "audit.html",
        state=context.store.display_state(),
        events=_audit_tail(limit),
        limit=limit,
    )


@bp.get("/system")
def system():
    context = get_context()
    settings = context.settings
    state = context.store.display_state()
    secrets_info = []
    for name, path in (
        ("凭证文件", settings.credentials_path),
        ("初始凭据（待确认）", settings.initial_credentials_path),
        ("Flask 会话密钥", settings.flask_secret_path),
        ("状态 MAC 密钥", settings.state_mac_path),
        ("IPC HMAC 密钥", settings.ipc_hmac_path),
        ("口令 MAC 密钥", settings.code_mac_path),
    ):
        secrets_info.append({"name": name, "exists": path.exists()})
    broker = _broker_status(context)
    broker_identity = None
    if broker.get("status") == "ok":
        broker_identity = {
            "key_id": broker.get("key_id"),
            "fingerprint": broker.get("fingerprint"),
        }
    return render_template(
        "system.html",
        state=state,
        settings=settings,
        secrets_info=secrets_info,
        broker=broker,
        broker_identity=broker_identity,
    )


def _upload_context() -> dict:
    context = get_context()
    broker_fingerprint = ""
    broker_error = ""
    try:
        identity = context.broker.call("get_identity", {})["identity"]
        broker_fingerprint = str(identity.get("fingerprint") or "")
    except Exception as exc:  # noqa: BLE001 - 页面仍需可打开
        broker_error = type(exc).__name__
    return {
        "enabled": context.settings.web_upload,
        "broker_fingerprint": broker_fingerprint,
        "broker_error": broker_error,
        "state": context.store.display_state(),
    }


@bp.get("/upload")
def upload():
    return render_template(
        "upload.html",
        error="",
        form={},
        **_upload_context(),
    )


@bp.post("/upload")
def upload_submit():
    context = get_context()
    form = {
        "codes": request.form.get("codes", "1"),
        "max_uses": request.form.get("max_uses", "1"),
        "expires": request.form.get("expires", "7d"),
        "max_codes": request.form.get("max_codes", "50"),
        "note": request.form.get("note", ""),
        "local_payload": request.form.get("local_payload") == "1",
    }
    error = ""
    try:
        codes = int(form["codes"])
        max_uses = int(form["max_uses"])
        limit_raw = form["max_codes"].strip()
        max_codes = int(limit_raw) if limit_raw else 50
        note = normalize_note(form["note"])
        if max_codes < codes:
            error = "口令总数上限不能小于本次生成数量"
        elif not 1 <= max_codes <= 10_000:
            error = "口令总数上限必须在 1..10000 之间"
    except ValueError:
        error = "口令数量、每个口令的次数与总数上限必须是整数"
    except ValidationError as exc:
        error = exc.message
    if error:
        return (
            render_template(
                "upload.html", error=error, form=form, **_upload_context()
            ),
            400,
        )
    try:
        result = run_web_upload(
            context,
            username=g.vaultshare_session.username,
            remote_addr=request.remote_addr or "unknown",
            package_files=request.files.getlist("package_files"),
            identity_files=request.files.getlist("identity_files"),
            password=request.form.get("identity_password", ""),
            codes=codes,
            max_uses=max_uses,
            expires=form["expires"],
            local_payload=form["local_payload"],
            max_codes=max_codes,
        )
    except VaultShareError as exc:
        return (
            render_template(
                "upload.html",
                error=exc.message,
                form=form,
                **_upload_context(),
            ),
            exc.status,
        )
    if note:
        context.notes.set_package_note(result.package_id, note)
        context.audit(
            "package_note_updated",
            package_id=result.package_id,
            by=g.vaultshare_session.username,
        )
    return render_template(
        "upload_result.html",
        result=result,
        note=note,
        state=context.store.display_state(),
    )


def _render_package_detail(package_id: str, *, error: str = "", form: dict | None = None):
    context = get_context()
    state = context.store.display_state()
    body = state.get("body") or {}
    package = body.get("packages", {}).get(package_id)
    if not isinstance(package, dict):
        return render_template("error.html", status=404, message="包不存在"), 404

    context_error = ""
    try:
        load_package_context(
            context.settings, body, package_id, require_active=False
        )
    except Exception as exc:  # noqa: BLE001 - 详情页要能展示损坏原因
        context_error = str(getattr(exc, "message", exc))

    notes = _notes()
    grants = []
    for grant_id, grant in (body.get("grants") or {}).items():
        if not isinstance(grant, dict) or grant.get("package_id") != package_id:
            continue
        grants.append(
            {
                "grant_id": grant_id,
                "note": notes["grants"].get(grant_id, ""),
                "created_text": format_iso(grant.get("created_at", 0)),
                "expires_text": format_iso(grant.get("expires_at", 0)),
                "expired": int(grant.get("expires_at", 0)) < now(),
                "max_uses": grant.get("max_uses", 0),
                "used": grant.get("used", 0),
                "revoked": bool(grant.get("revoked")),
                "batch_id": grant.get("batch_id", ""),
                "sealed": bool(grant.get("sealed_code")),
            }
        )
    grants.sort(key=lambda item: item["created_text"], reverse=True)
    metrics = grant_metrics(body.get("grants", {}), package_id)
    sender = (body.get("senders") or {}).get(package.get("sender_key_id"), {})

    return render_template(
        "package.html",
        package_id=package_id,
        package=package,
        package_view={
            "status": package.get("status"),
            "created_text": format_iso(package.get("created_at", 0)),
            "payload_sha256": package.get("payload_sha256", ""),
            "payload_mode": package.get("payload_mode", "server"),
            "keyconfig_sha256": package.get("keyconfig_sha256", ""),
            "policy_sha256": package.get("policy_sha256", ""),
            "broker_key_id": package.get("broker_key_id", ""),
            "sender_key_id": package.get("sender_key_id", ""),
        },
        package_note=notes["packages"].get(package_id, ""),
        sender=sender,
        grants=grants,
        metrics=metrics,
        context_error=context_error,
        error=error,
        form=form or {},
        state=state,
    )


@bp.get("/packages/<package_id>")
def package_detail(package_id: str):
    return _render_package_detail(package_id)


def _authorized_mutation(context) -> None:
    """Web 写操作统一要求：已登录（before_request 已保证）+ CSRF。"""
    check_csrf(g.vaultshare_session.csrf_token, request.form.get("csrf_token"))


@bp.post("/packages/<package_id>/revoke")
def revoke_package(package_id: str):
    context = get_context()
    _authorized_mutation(context)

    def mutate(body: dict) -> None:
        package = body["packages"].get(package_id)
        if not isinstance(package, dict):
            raise ValidationError("包不存在", code="package_unknown")
        body.setdefault("revoked_packages", {})[package_id] = now()
        package["status"] = "revoked"
        for grant in body.get("grants", {}).values():
            if isinstance(grant, dict) and grant.get("package_id") == package_id:
                grant["revoked"] = True

    context.store.transaction(mutate)
    context.audit("package_revoked", package_id=package_id, by="web")
    flash("包及其全部口令已撤销。", "ok")
    return redirect(url_for("web.package_detail", package_id=package_id))


@bp.post("/packages/<package_id>/grants/<grant_id>/revoke")
def revoke_grant(package_id: str, grant_id: str):
    context = get_context()
    _authorized_mutation(context)

    def mutate(body: dict) -> None:
        grant = body["grants"].get(grant_id)
        if not isinstance(grant, dict) or grant.get("package_id") != package_id:
            raise ValidationError("授权不存在", code="grant_unknown")
        grant["revoked"] = True

    context.store.transaction(mutate)
    context.audit("grant_revoked", package_id=package_id, grant_id=grant_id, by="web")
    flash("该口令已撤销。", "ok")
    return redirect(url_for("web.package_detail", package_id=package_id))


def _detail_error(package_id: str, message: str, form: dict | None = None, status: int = 400):
    rendered = _render_package_detail(package_id, error=message, form=form or {})
    if isinstance(rendered, tuple):
        return rendered
    return rendered, status


@bp.post("/packages/<package_id>/note")
def update_package_note(package_id: str):
    context = get_context()
    _authorized_mutation(context)
    body = context.store.snapshot()["body"]
    if not isinstance((body.get("packages") or {}).get(package_id), dict):
        return render_template("error.html", status=404, message="包不存在"), 404
    try:
        note = context.notes.set_package_note(
            package_id, request.form.get("note", "")
        )
    except ValidationError as exc:
        return _detail_error(package_id, exc.message, status=exc.status)
    context.audit(
        "package_note_updated",
        package_id=package_id,
        length=len(note),
        by=g.vaultshare_session.username,
    )
    flash("包备注已保存。" if note else "包备注已清空。", "ok")
    return redirect(url_for("web.package_detail", package_id=package_id))


@bp.post("/packages/<package_id>/grants/notes")
def update_grant_notes(package_id: str):
    context = get_context()
    _authorized_mutation(context)
    body = context.store.snapshot()["body"]
    if not isinstance((body.get("packages") or {}).get(package_id), dict):
        return render_template("error.html", status=404, message="包不存在"), 404
    valid = {
        grant_id
        for grant_id, grant in (body.get("grants") or {}).items()
        if isinstance(grant, dict) and grant.get("package_id") == package_id
    }
    changes = {
        key[5:]: value
        for key, value in request.form.items()
        if key.startswith("note_") and key[5:] in valid
    }
    try:
        context.notes.set_grant_notes(changes)
    except ValidationError as exc:
        return _detail_error(package_id, exc.message, status=exc.status)
    context.audit(
        "grant_notes_updated",
        package_id=package_id,
        count=len(changes),
        by=g.vaultshare_session.username,
    )
    flash(f"已保存 {len(changes)} 条口令备注。", "ok")
    return redirect(url_for("web.package_detail", package_id=package_id))


@bp.post("/packages/<package_id>/grants")
def add_grants(package_id: str):
    context = get_context()
    _authorized_mutation(context)
    form = {
        "codes": request.form.get("codes", "1"),
        "max_uses": request.form.get("max_uses", "1"),
        "expires": request.form.get("expires", "7d"),
    }
    try:
        codes = int(form["codes"])
        max_uses = int(form["max_uses"])
    except ValueError:
        return _detail_error(
            package_id, "口令数量与每个口令的次数必须是整数", form
        )
    try:
        result = run_web_add_grants(
            context,
            package_id=package_id,
            username=g.vaultshare_session.username,
            remote_addr=request.remote_addr or "unknown",
            identity_files=request.files.getlist("identity_files"),
            password=request.form.get("identity_password", ""),
            codes=codes,
            max_uses=max_uses,
            expires=form["expires"],
        )
    except VaultShareError as exc:
        return _detail_error(package_id, exc.message, form, status=exc.status)
    return render_template(
        "grants_added.html",
        result=result,
        state=context.store.display_state(),
    )
