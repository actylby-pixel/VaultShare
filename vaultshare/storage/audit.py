"""追加式审计日志。

事件只记录事实与标识符，**绝不记录**口令、``K_pkg``、私钥、密文正文或可重放的
认证材料。每条写入后 fsync；写失败不会让业务流程“假装成功”，而是打印到
stderr——审计不可写本身是必须让人看见的故障。
"""

from __future__ import annotations

import json
import os
import sys
import threading

from ..util.timeutil import now
from . import permissions

__all__ = ["AuditLog"]

_SECRET_KEYS = {
    "password",
    "code",
    "k_pkg",
    "private_key",
    "secret",
    "token",
    "totp_secret",
    "code_verifier",
}


class AuditLog:
    def __init__(self, path: str):
        self.path = os.fspath(path)
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        created = not os.path.exists(self.path)
        if created:
            with open(self.path, "ab"):
                pass
            permissions.tighten(self.path)
        permissions.tighten(directory, directory=True)

    def write(self, event: str, **fields) -> None:
        record = {"ts": now(), "event": str(event)}
        for key, value in fields.items():
            if key in _SECRET_KEYS:
                record[key] = "[redacted]"
            elif isinstance(value, (str, int, float, bool)) or value is None:
                record[key] = value
            else:
                record[key] = str(value)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as exc:
                print(f"审计写入失败：{exc}", file=sys.stderr)

    __call__ = write
