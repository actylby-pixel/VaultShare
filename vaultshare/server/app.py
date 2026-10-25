"""Flask 应用工厂。

启动顺序：
1. 收紧目录/密钥文件权限；
2. 获取 ``writer.lock``（单写者）；拿不到就拒绝启动；
3. 加载并校验状态（损坏 → 降级模式，但仍允许只读页面）；
4. 预置代理密钥并确保状态中的 ``current_key_id``；
5. 首次生成凭证（TTY 打印一次；非 TTY 写入 0600 一次性文件）。

Web 与 API 的认证完全分离：Web 用服务端会话 + CSRF，API 只认 Bearer token，
且显式拒绝 Cookie 认证。
"""

from __future__ import annotations

import atexit
import secrets
from dataclasses import dataclass

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

from ..broker.ipc import IpcClient
from ..config import Settings, load_settings, normalize_url_prefix
from ..errors import NotAuthenticated, VaultShareError
from ..storage import permissions
from ..storage.atomic import cleanup_temp_files
from ..storage.audit import AuditLog
from ..storage.locking import LockTimeout, FileLock
from ..storage.notes import NoteStore
from ..storage.secrets import init_secret_files, read_flask_secret, read_ipc_key, read_state_mac_key
from ..storage.state import StateStore
from ..util.timeutil import now
from ..version import __version__
from .auth import CredentialsStore, SessionManager
from .ratelimit import LoginRateLimiter, SlidingWindowLimiter, check_csrf
from .provision import provision

from werkzeug.middleware.proxy_fix import ProxyFix

__all__ = ["VaultShareContext", "create_app", "get_context"]


@dataclass
class VaultShareContext:
    settings: Settings
    store: StateStore
    audit: AuditLog
    credentials: CredentialsStore
    sessions: SessionManager
    limiter: LoginRateLimiter
    broker: IpcClient
    secret: bytes
    login_window: SlidingWindowLimiter
    redeem_window: SlidingWindowLimiter
    notes: NoteStore | None = None
    writer_lock: FileLock | None = None


def get_context() -> VaultShareContext:
    return g._vaultshare_context


class _PrefixFallback:
    """让 ``VAULTSHARE_URL_PREFIX`` 在反向代理不发送前缀头时也生效。

    ``ProxyFix(x_prefix=1)`` 会把 ``X-Forwarded-Prefix`` 放进 ``SCRIPT_NAME``，
    此时本中间件不做任何事。若代理没有提供前缀，就使用配置值，并把直接访问
    ``/vault/...`` 时多出来的前缀从 ``PATH_INFO`` 里剥掉，避免路由重复匹配。
    """

    def __init__(self, app, prefix: str) -> None:
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        script = environ.get("SCRIPT_NAME") or ""
        path = environ.get("PATH_INFO") or ""
        # 某些代理会同时设置 SCRIPT_NAME 又保留完整路径；剥掉重复前缀。
        if script and (path == script or path.startswith(script + "/")):
            environ["PATH_INFO"] = path[len(script):] or "/"
        elif not script:
            if path == self.prefix or path.startswith(self.prefix + "/"):
                environ["PATH_INFO"] = path[len(self.prefix):] or "/"
            environ["SCRIPT_NAME"] = self.prefix
        return self.app(environ, start_response)


def _client_ip() -> str:
    # 不信任 X-Forwarded-For：反代部署时由管理员在 README 中了解该限制。
    return request.remote_addr or "unknown"


def create_app(
    settings: Settings | None = None,
    *,
    acquire_writer: bool = True,
    do_provision: bool = True,
    force_print_credentials: bool = False,
) -> Flask:
    settings = settings or load_settings()
    settings.ensure_dirs()
    init_secret_files(settings)
    permissions.tighten(str(settings.data_dir), directory=True)
    permissions.tighten(str(settings.secrets_dir), directory=True)
    cleanup_temp_files(settings.data_dir)

    writer_lock = None
    if acquire_writer:
        try:
            writer_lock = FileLock(str(settings.locks_dir / "writer.lock"), timeout=0.5).acquire()
        except LockTimeout as exc:
            raise RuntimeError("已有另一个 VaultShare 服务进程在运行（writer.lock 被占用）") from exc

    audit = AuditLog(str(settings.audit_path))
    mac_key = read_state_mac_key(settings)
    store = StateStore(settings, mac_key, audit)
    store.startup()

    initial = None
    if do_provision and not store.degraded:
        initial = provision(settings, store, force_print=force_print_credentials)
    elif not CredentialsStore(settings).exists():
        # 状态损坏时仍生成凭证，至少让管理员能登录查看看板（若状态恢复）。
        from .auth import provisioning_uri

        creds_store = CredentialsStore(settings)
        creds, password = creds_store.create_initial()
        from .provision import InitialCredentials, print_initial_credentials

        initial = InitialCredentials(settings, creds.username, password, provisioning_uri(creds))
        print_initial_credentials(initial, force_print=force_print_credentials)

    context = VaultShareContext(
        settings=settings,
        store=store,
        audit=audit,
        credentials=CredentialsStore(settings),
        sessions=SessionManager(timeout=settings.session_timeout),
        limiter=LoginRateLimiter(store),
        broker=IpcClient(
            settings.broker_host,
            settings.broker_port,
            read_ipc_key(settings),
        ),
        secret=read_flask_secret(settings),
        login_window=SlidingWindowLimiter(20, 60),
        redeem_window=SlidingWindowLimiter(60, 60),
        notes=NoteStore(settings.notes_path),
        writer_lock=writer_lock,
    )

    app = Flask(__name__, template_folder="templates", static_folder="static")
    # 反向代理部署在子路径时（例如 Nginx ``location /vault/``）：
    # * 代理转发 ``X-Forwarded-Prefix: /vault``，ProxyFix 会把它放进
    #   SCRIPT_NAME，url_for() 随之生成 /vault/...；
    # * 若代理不带该头，可设置 VAULTSHARE_URL_PREFIX=/vault，这里写入
    #   APPLICATION_ROOT 让 URL 生成与会话 Cookie 路径也带上子路径。
    # 两者都不设时就是直接访问根路径，默认行为不变。
    app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)
    prefix = normalize_url_prefix(settings.url_prefix)
    if prefix:
        app.wsgi_app = _PrefixFallback(app.wsgi_app, prefix)
    app.secret_key = context.secret
    app.config.update(
        SESSION_COOKIE_NAME="vaultshare_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=settings.https,
        PERMANENT_SESSION_LIFETIME=settings.session_timeout,
        MAX_CONTENT_LENGTH=settings.upload_max_bytes + 1024 * 1024,
        JSON_SORT_KEYS=False,
    )
    if prefix:
        app.config["APPLICATION_ROOT"] = prefix
    app.json.ensure_ascii = False
    app.extensions["vaultshare"] = context
    app.extensions["vaultshare_initial_credentials"] = initial

    from . import routes_api, routes_web

    app.register_blueprint(routes_web.bp)
    app.register_blueprint(routes_api.bp)

    @app.before_request
    def _attach_context() -> None:
        g._vaultshare_context = context
        if request.path.startswith("/api/") or request.endpoint == "static":
            return
        if request.endpoint == "web.login":
            # 登录表单的 CSRF 在路由内校验，这样失败时可以留在登录页显示提示，
            # 而不是跳到通用错误页。
            if "pre_csrf" not in session:
                session["pre_csrf"] = secrets.token_urlsafe(32)
            return
        sid = session.get("sid")
        current = context.sessions.get(sid)
        if current is None:
            session.clear()
            if request.method in ("GET", "HEAD"):
                return redirect(url_for("web.login"))
            raise NotAuthenticated("请先登录")
        g.vaultshare_session = current
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            check_csrf(current.csrf_token, token)

    @app.context_processor
    def _inject_globals():
        token = ""
        current = g.get("vaultshare_session")
        if current is not None:
            token = current.csrf_token
        else:
            token = session.get("pre_csrf", "")
        return {
            "csrf_token": token,
            "app_version": __version__,
            "now_ts": now(),
            "web_upload_enabled": bool(settings.web_upload),
            "url_prefix": prefix,
        }

    @app.after_request
    def _headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if not request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if settings.https:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(VaultShareError)
    def _business_error(exc: VaultShareError):
        if request.path.startswith("/api/"):
            return jsonify({"error": exc.code, "message": exc.message}), exc.status
        return (
            render_template("error.html", status=exc.status, message=exc.message),
            exc.status,
        )

    @app.errorhandler(413)
    def _too_large(_exc):
        if request.path.startswith("/api/"):
            return jsonify({"error": "too_large", "message": "请求体超过大小上限"}), 413
        return render_template("error.html", status=413, message="请求体超过大小上限"), 413

    def _shutdown() -> None:
        lock = context.writer_lock
        if lock is not None:
            try:
                lock.release()
            except Exception:  # noqa: BLE001
                pass
            context.writer_lock = None

    app.extensions["vaultshare_shutdown"] = _shutdown
    atexit.register(_shutdown)
    return app
