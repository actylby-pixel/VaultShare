"""时间与时长解析。

协议里的时间统一为 UTC epoch 秒（整数）。期限解析只接受整数 + 单位，拒绝
浮点数与负数，避免 ``7.9d`` 被悄悄截断成 ``7d``。
"""

from __future__ import annotations

import re
import time

__all__ = ["now", "parse_duration", "parse_iso", "format_iso"]

_DUR_RE = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def now() -> int:
    return int(time.time())


def parse_duration(value: str) -> int:
    """``7d`` / ``12h`` / ``90m`` → 秒。只接受正整数。"""
    if not isinstance(value, str):
        raise ValueError("时长必须是字符串")
    match = _DUR_RE.match(value.strip().lower())
    if not match:
        raise ValueError("时长格式应为 <正整数><s|m|h|d|w>，例如 7d")
    return int(match.group(1)) * _UNITS[match.group(2)]


def parse_iso(value: str) -> int:
    """ISO-8601（``2026-01-01T00:00:00Z``）→ epoch 秒。"""
    from datetime import datetime, timezone

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("非法的时间格式") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def format_iso(ts: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
