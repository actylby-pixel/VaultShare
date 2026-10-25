"""单用户认证：凭证文件、TOTP、服务端会话、Bearer token。

凭证文件是可编辑的 UTF-8 INI::

    [account]
    username = admin
    password_hash = scrypt:...
    totp_secret = BASE32...
    created_at = 1234567890

密码只保存 Werkzeug scrypt 哈希。TOTP 密钥是明文（记事本可编辑的代价），
只能靠文件权限保护；README 明说这**不是**独立第二因素，因为能读文件的
人也能读 TOTP 密钥。

登录成功要求：用户名、密码、TOTP 三项全部正确，且 TOTP 时间步严格大于
``state.auth.last_totp_step``（防重放）。这三项在同一把状态锁内提交。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass

import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

from ..config import Settings
from ..errors import Forbidden, NotAuthenticated, ValidationError
from ..storage import permissions
from ..storage.atomic import atomic_write_bytes
from ..util.canonical import b64u_decode, b64u_encode, canonical_bytes

__all__ = [
    "Credentials",
    "CredentialsStore",
    "SessionManager",
    "Session",
    "issue_bearer",
    "verify_bearer",
    "match_totp_step",
    "TOTP_DIGITS",
    "TOTP_INTERVAL",
]

TOTP_DIGITS = 6
TOTP_INTERVAL = 30
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_TOTP_RE = re.compile(r"^\d{6}$")


@dataclass(frozen=True)
class Credentials:
    username: str
    password_hash: str
    totp_secret: str
    created_at: int


class CredentialsStore:
    def __init__(self, settings: Settings):
        self.path = str(settings.credentials_path)

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def load(self) -> Credentials:
        try:
            with open(self.path, "r", encoding="utf-8-sig") as f:
                text = f.read()
        except OSError as exc:
            raise NotAuthenticated("凭证文件不可读") from exc
        values: dict[str, str] = {}
        section = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if section == "account":
                values[key.strip().lower()] = value.strip()
        try:
            username = values["username"]
            password_hash = values["password_hash"]
            totp_secret = values["totp_secret"]
            created_at = int(values.get("created_at", "0"))
        except (KeyError, ValueError) as exc:
            raise NotAuthenticated("凭证文件缺少必要字段") from exc
        if not _USERNAME_RE.match(username):
            raise NotAuthenticated("凭证文件中的用户名非法")
        if not password_hash.startswith("scrypt:") and not password_hash.startswith("pbkdf2:"):
            raise NotAuthenticated("凭证文件中的密码哈希格式非法")
        try:
            base64.b32decode(totp_secret.upper() + "=" * (-len(totp_secret) % 8))
        except Exception as exc:  # noqa: BLE001
            raise NotAuthenticated("凭证文件中的 TOTP 密钥非法") from exc
        return Credentials(username, password_hash, totp_secret.upper(), created_at)

    def save(self, creds: Credentials) -> None:
        if not _USERNAME_RE.match(creds.username):
            raise ValidationError("用户名非法")
        text = (
            "# VaultShare 凭证文件（UTF-8，可用记事本编辑）\n"
            "# 密码字段必须保留为 Werkzeug 哈希；不要在这里写明文密码。\n"
            "[account]\n"
            f"username = {creds.username}\n"
            f"password_hash = {creds.password_hash}\n"
            f"totp_secret = {creds.totp_secret}\n"
            f"created_at = {int(creds.created_at)}\n"
        )
        atomic_write_bytes(self.path, text.encode("utf-8"))
        permissions.tighten(self.path)

    def create_initial(self, username: str = "admin") -> tuple[Credentials, str]:
        password = secrets.token_urlsafe(18)
        secret = pyotp.random_base32()
        creds = Credentials(
            username=username,
            password_hash=generate_password_hash(password, method="scrypt"),
            totp_secret=secret,
            created_at=int(time.time()),
        )
        self.save(creds)
        return creds, password


def provisioning_uri(creds: Credentials) -> str:
    return pyotp.TOTP(creds.totp_secret).provisioning_uri(
        name=creds.username, issuer_name="VaultShare"
    )


def match_totp_step(secret: str, code: str, now: int | None = None) -> int | None:
    """返回匹配的时间步；不匹配返回 None。只接受 6 位数字。"""
    if not isinstance(code, str) or not _TOTP_RE.match(code):
        return None
    current = int(time.time() if now is None else now)
    try:
        totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    except Exception:  # noqa: BLE001
        return None
    for offset in (-TOTP_INTERVAL, 0, TOTP_INTERVAL):
        moment = current + offset
        try:
            expected = totp.at(moment)
        except Exception:  # noqa: BLE001
            return None
        if hmac.compare_digest(str(expected), code):
            return moment // TOTP_INTERVAL
    return None


def verify_password(creds: Credentials, password: str) -> bool:
    if not isinstance(password, str):
        return False
    try:
        return check_password_hash(creds.password_hash, password)
    except Exception:  # noqa: BLE001 - 哈希格式损坏按失败处理
        return False


@dataclass
class Session:
    sid: str
    username: str
    csrf_token: str
    created_at: float
    last_seen: float


class SessionManager:
    """进程内会话表。

    只把随机 ``sid`` 放进签名 Cookie。服务端保存 CSRF token 与最后活跃时间，
    登录时生成全新 sid（会话固定防护），登出立即失效。重启会让所有会话失效，
    这比把会话写进磁盘更保守。
    """

    def __init__(self, timeout: int = 30 * 60):
        self.timeout = timeout
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}

    def create(self, username: str) -> Session:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        stamp = time.time()
        session = Session(sid, username, csrf, stamp, stamp)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, sid: str | None, touch: bool = True) -> Session | None:
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            now = time.time()
            if now - session.last_seen > self.timeout:
                self._sessions.pop(sid, None)
                return None
            if touch:
                session.last_seen = now
            return session

    def destroy(self, sid: str | None) -> None:
        if not sid:
            return
        with self._lock:
            self._sessions.pop(sid, None)

    def sweep(self) -> None:
        now = time.time()
        with self._lock:
            stale = [sid for sid, s in self._sessions.items() if now - s.last_seen > self.timeout]
            for sid in stale:
                self._sessions.pop(sid, None)


# ------------------------------------------------------------------ Bearer
def _token_mac(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(secret, b"vaultshare-token-v1\0" + payload, hashlib.sha256).digest()


def issue_bearer(
    secret: bytes, username: str, epoch: int, *, ttl: int = 30 * 60
) -> tuple[str, int]:
    issued = int(time.time())
    expires = issued + int(ttl)
    payload = canonical_bytes(
        {
            "v": 1,
            "sub": username,
            "epoch": int(epoch),
            "iat": issued,
            "exp": expires,
            "jti": secrets.token_urlsafe(16),
        }
    )
    token = (
        "vs1."
        + b64u_encode(payload)
        + "."
        + b64u_encode(_token_mac(secret, payload))
    )
    return token, expires


def verify_bearer(secret: bytes, token: str, current_epoch: int) -> str:
    """返回用户名；任何问题都抛 ``NotAuthenticated``。"""
    if not isinstance(token, str) or not token.startswith("vs1."):
        raise NotAuthenticated("Bearer token 格式非法")
    parts = token.split(".")
    if len(parts) != 3:
        raise NotAuthenticated("Bearer token 格式非法")
    try:
        payload = b64u_decode(parts[1])
        signature = b64u_decode(parts[2])
    except ValueError as exc:
        raise NotAuthenticated("Bearer token 编码非法") from exc
    if not hmac.compare_digest(signature, _token_mac(secret, payload)):
        raise NotAuthenticated("Bearer token 签名无效")
    import json

    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NotAuthenticated("Bearer token 载荷非法") from exc
    if not isinstance(data, dict) or data.get("v") != 1:
        raise NotAuthenticated("Bearer token 版本非法")
    if not isinstance(data.get("sub"), str) or not isinstance(data.get("exp"), int):
        raise NotAuthenticated("Bearer token 字段非法")
    if data["exp"] < int(time.time()):
        raise NotAuthenticated("Bearer token 已过期")
    if int(data.get("epoch", -1)) != int(current_epoch):
        raise NotAuthenticated("Bearer token 已失效（认证纪元已更新）")
    return data["sub"]
