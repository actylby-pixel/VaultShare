"""代理侧幂等记录（跨重启）。

用途：
* ``grants:<batch_id>`` —— 同一批次重试返回同一组口令密文；
* ``authorize:<request_id>:<body_sha256>`` —— 重试返回同一张预授权票据。

条目带过期时间并持久化到 ``data/broker/idempotency.json``。文件损坏视为
代理不可用（而不是“缓存清空继续跑”）——否则一次重试可能重复发码。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from ..config import Settings
from ..errors import Unavailable
from ..storage import permissions
from ..storage.atomic import atomic_write_json, read_bytes
from ..util.timeutil import now

__all__ = ["IdempotencyStore"]

MAX_ENTRIES = 20_000
_FORMAT = "vaultshare-broker-idempotency"


class IdempotencyStore:
    def __init__(self, settings: Settings):
        self.path = settings.idempotency_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        permissions.tighten(str(self.path.parent), directory=True)
        self._lock = threading.RLock()
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(read_bytes(str(self.path)).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Unavailable("代理幂等记录损坏，拒绝启动") from exc
        if not isinstance(data, dict) or data.get("format") != _FORMAT:
            raise Unavailable("代理幂等记录格式不匹配")
        entries = data.get("entries")
        if not isinstance(entries, dict):
            raise Unavailable("代理幂等记录结构非法")
        current = now()
        self._entries = {
            key: value
            for key, value in entries.items()
            if isinstance(value, dict) and int(value.get("expires_at", 0)) > current
        }

    def _save(self) -> None:
        if len(self._entries) > MAX_ENTRIES:
            ordered = sorted(
                self._entries.items(), key=lambda kv: int(kv[1].get("expires_at", 0))
            )
            self._entries = dict(ordered[-MAX_ENTRIES:])
        atomic_write_json(
            str(self.path),
            {"format": _FORMAT, "version": 1, "entries": self._entries},
        )
        permissions.tighten(str(self.path))

    def get(self, key: str) -> object | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if int(entry.get("expires_at", 0)) <= now():
                self._entries.pop(key, None)
                self._save()
                return None
            return entry.get("value")

    def put(self, key: str, value, *, ttl: int) -> None:
        with self._lock:
            self._entries[key] = {"expires_at": now() + int(ttl), "value": value}
            self._save()

    def delete(self, key: str) -> None:
        with self._lock:
            if self._entries.pop(key, None) is not None:
                self._save()
