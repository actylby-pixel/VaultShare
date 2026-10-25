"""代理信封缓存（跨重启）。

键是 ``request_id``，值里保存 ``body_sha256``：同一 ``request_id`` 若携带不同
请求内容，一律拒绝。缓存只保存已经由代理签名的信封，不保存 ``K_pkg``。

原子写入，权限收紧。读取失败视为缓存缺失，但内容摘要不一致是硬错误。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..config import Settings
from ..errors import ValidationError
from ..storage import permissions
from ..storage.atomic import atomic_write_json, read_bytes
from ..util.ids import REQUEST_ID_BYTES, is_hex_id
from ..util.timeutil import now

__all__ = ["EnvelopeCache"]


class EnvelopeCache:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.directory = settings.envelopes_dir
        self.directory.mkdir(parents=True, exist_ok=True)
        permissions.tighten(str(self.directory), directory=True)

    def _path(self, request_id: str) -> Path:
        if not is_hex_id(request_id, REQUEST_ID_BYTES):
            raise ValidationError("request_id 格式非法")
        return self.directory / f"{request_id}.json"

    def get(self, request_id: str, body_sha256: str) -> dict | None:
        path = self._path(request_id)
        if not path.exists():
            return None
        try:
            record = json.loads(read_bytes(str(path)).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(record, dict):
            return None
        if record.get("body_sha256") != body_sha256:
            raise ValidationError(
                "同一 request_id 携带了不同的请求内容", code="request_id_reuse"
            )
        envelope = record.get("envelope")
        if not isinstance(envelope, dict):
            return None
        return envelope

    def put(self, request_id: str, body_sha256: str, envelope: dict) -> None:
        record = {
            "request_id": request_id,
            "body_sha256": body_sha256,
            "created_at": now(),
            "envelope": envelope,
        }
        path = self._path(request_id)
        atomic_write_json(str(path), record)
        permissions.tighten(str(path))
