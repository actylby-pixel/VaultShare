"""共享包与口令的备注。

备注只是给管理员看的展示文字：不参与签名、不进入状态文件、也不影响授权与
兑换。单独存一个 ``data/notes.json``，避免把随便输入的文本塞进受 MAC 与
journal 约束的 ``state.json``（状态里的授权记录字段集合是严格校验的）。

并发：Web 是单写者进程，这里再用线程锁把「读 → 改 → 原子替换」串行化。
文件损坏时按空备注处理并记一条 warning，不让管理页面整体 500。
"""

from __future__ import annotations

import copy
import json
import logging
import threading
from pathlib import Path

from ..errors import ValidationError
from .atomic import atomic_write_bytes

__all__ = ["MAX_NOTE_CHARS", "NoteStore", "normalize_note"]

MAX_NOTE_CHARS = 500
_MAX_FILE_BYTES = 4 * 1024 * 1024

_log = logging.getLogger(__name__)


def normalize_note(raw: str | None) -> str:
    """统一换行、去掉控制字符与首尾空白，并限制长度。"""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ValidationError("备注必须是文本")
    text = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
    text = "".join(
        ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32
    )
    if len(text) > MAX_NOTE_CHARS:
        raise ValidationError(f"备注不能超过 {MAX_NOTE_CHARS} 个字符")
    return text


def _empty() -> dict:
    return {"packages": {}, "grants": {}}


class NoteStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ 读取
    def _load(self) -> dict:
        try:
            size = self.path.stat().st_size
        except OSError:
            return _empty()
        if size > _MAX_FILE_BYTES:
            _log.warning("notes 文件过大，已忽略：%s", self.path)
            return _empty()
        try:
            data = json.loads(self.path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            _log.warning("notes 文件无法解析，按空备注处理：%s", exc)
            return _empty()
        if not isinstance(data, dict):
            return _empty()
        result = _empty()
        for section in ("packages", "grants"):
            values = data.get(section)
            if isinstance(values, dict):
                for key, value in values.items():
                    if isinstance(key, str) and isinstance(value, str) and value:
                        result[section][key] = value
        return result

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._load())

    def package_notes(self) -> dict[str, str]:
        return self.snapshot()["packages"]

    def grant_notes(self) -> dict[str, str]:
        return self.snapshot()["grants"]

    # ------------------------------------------------------------ 写入
    def _write(self, data: dict) -> None:
        payload = json.dumps(
            data, ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(str(self.path), payload)

    def set_package_note(self, package_id: str, note: str) -> str:
        text = normalize_note(note)
        with self._lock:
            data = self._load()
            if text:
                data["packages"][package_id] = text
            else:
                data["packages"].pop(package_id, None)
            self._write(data)
        return text

    def set_grant_notes(self, notes: dict[str, str]) -> int:
        """批量更新若干个口令备注；空字符串表示删除。返回实际写入的条数。"""
        normalized = {gid: normalize_note(text) for gid, text in notes.items()}
        with self._lock:
            data = self._load()
            changed = 0
            for grant_id, text in normalized.items():
                if text:
                    if data["grants"].get(grant_id) != text:
                        changed += 1
                    data["grants"][grant_id] = text
                else:
                    if grant_id in data["grants"]:
                        changed += 1
                        data["grants"].pop(grant_id, None)
            self._write(data)
        return changed
