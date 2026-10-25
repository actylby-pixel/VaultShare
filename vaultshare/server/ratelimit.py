"""登录失败限速与会话内 CSRF。

限速计数持久化在状态文件的 ``body.auth.lockouts`` 中，因此重启不会清零。
前 4 次失败只记录；第 5 次开始锁定，时长按指数增长，上限 1 小时。

CSRF token 存在服务端会话中，Web 表单与 ``X-CSRF-Token`` 都接受。API 路由
使用 Bearer token，**禁止 Cookie 认证**，因此不参与 CSRF 校验。
"""

from __future__ import annotations

import collections
import hmac
import threading
import time

from ..errors import Forbidden, ValidationError
from ..storage.state import StateStore
from ..util.timeutil import now

__all__ = ["LoginRateLimiter", "SlidingWindowLimiter", "check_csrf"]

FREE_ATTEMPTS = 4
BASE_LOCK = 60
MAX_LOCK = 3600


class LoginRateLimiter:
    def __init__(self, state: StateStore):
        self.state = state

    @staticmethod
    def key(username: str, ip: str) -> str:
        return f"{(username or '')[:64]}|{(ip or '')[:64]}"

    def check(self, username: str, ip: str) -> None:
        key = self.key(username, ip)
        body = self.state.snapshot()["body"]
        entry = body["auth"].get("lockouts", {}).get(key)
        if isinstance(entry, dict) and int(entry.get("locked_until", 0)) > now():
            raise Forbidden("登录尝试过于频繁，请稍后再试", code="locked_out")

    def failure(self, username: str, ip: str) -> dict:
        key = self.key(username, ip)

        def mutate(body):
            lockouts = body["auth"].setdefault("lockouts", {})
            entry = lockouts.get(key) or {"failures": 0, "locked_until": 0}
            failures = int(entry.get("failures", 0)) + 1
            locked_until = int(entry.get("locked_until", 0))
            if failures >= FREE_ATTEMPTS:
                duration = min(MAX_LOCK, BASE_LOCK * (2 ** (failures - FREE_ATTEMPTS)))
                locked_until = now() + duration
            lockouts[key] = {
                "failures": failures,
                "locked_until": locked_until,
                "last_failure": now(),
            }
            # 有界：防止用随机用户名把状态撑大。
            if len(lockouts) > 1000:
                ordered = sorted(
                    lockouts.items(), key=lambda kv: int(kv[1].get("last_failure", 0))
                )
                body["auth"]["lockouts"] = dict(ordered[-1000:])
            return {"failures": failures, "locked_until": locked_until}

        return self.state.transaction(mutate)

    def success(self, username: str, ip: str) -> None:
        key = self.key(username, ip)

        def mutate(body):
            body["auth"].setdefault("lockouts", {}).pop(key, None)

        self.state.transaction(mutate)


class SlidingWindowLimiter:
    """进程内滑动窗口限速，用于登录与兑换的粗粒度 DoS 防护。

    不是安全边界（重启清零、按进程计数），但能挡住最简单的暴力请求。
    """

    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._hits: dict[str, collections.deque] = {}

    def allow(self, key: str) -> bool:
        current = time.monotonic()
        with self._lock:
            queue = self._hits.setdefault(key, collections.deque())
            while queue and current - queue[0] > self.window:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(current)
            if len(self._hits) > 10_000:
                stale = [
                    k for k, q in self._hits.items() if not q or current - q[-1] > self.window
                ]
                for k in stale:
                    self._hits.pop(k, None)
            return True


def check_csrf(session_token: str | None, submitted: str | None) -> None:
    if not session_token or not submitted:
        raise ValidationError("缺少 CSRF token", code="csrf")
    if not hmac.compare_digest(str(session_token), str(submitted)):
        raise ValidationError("CSRF token 无效", code="csrf")
