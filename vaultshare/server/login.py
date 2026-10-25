"""用户名 + 密码 + TOTP 的统一认证流程（Web 与 API 共用）。

所有失败对调用方返回同一句话，避免区分“用户名错”“密码错”“验证码错”。
TOTP 时间步在状态事务里严格递增；重放同一个验证码会被拒绝并审计。
"""

from __future__ import annotations

import hmac

from ..errors import NotAuthenticated
from .auth import match_totp_step, verify_password

__all__ = ["authenticate"]

_FAIL_MESSAGE = "用户名、密码或验证码错误"


def authenticate(context, username: str, password: str, totp_code: str, ip: str) -> str:
    context.limiter.check(username, ip)
    try:
        creds = context.credentials.load()
    except NotAuthenticated:
        # 凭证文件损坏也是失败；不能把“文件坏了”暴露成可区分信号。
        context.limiter.failure(username, ip)
        context.audit("login_fail", reason="credentials_unreadable", ip=ip)
        raise NotAuthenticated(_FAIL_MESSAGE)

    username_ok = hmac.compare_digest(creds.username, username or "")
    # 无论用户名对错都做一次口令哈希校验，避免用响应时间枚举用户名。
    password_ok = verify_password(creds, password or "")
    step = match_totp_step(creds.totp_secret, totp_code or "")
    if not (username_ok and password_ok and step is not None):
        result = context.limiter.failure(username, ip)
        context.audit(
            "login_fail",
            username=username,
            ip=ip,
            failures=result.get("failures"),
            locked=bool(result.get("locked_until", 0) > 0),
        )
        raise NotAuthenticated(_FAIL_MESSAGE)

    def commit(body):
        last = int(body["auth"].get("last_totp_step", 0))
        if step <= last:
            raise NotAuthenticated("验证码已使用，请等待下一个验证码")
        body["auth"]["last_totp_step"] = int(step)
        body["auth"].setdefault("lockouts", {}).pop(context.limiter.key(username, ip), None)
        return int(body["auth"].get("api_epoch", 1))

    try:
        epoch = context.store.transaction(commit)
    except NotAuthenticated:
        context.audit("login_fail", username=username, ip=ip, reason="totp_replay")
        raise
    context.audit("login_ok", username=creds.username, ip=ip, epoch=epoch)
    return creds.username
