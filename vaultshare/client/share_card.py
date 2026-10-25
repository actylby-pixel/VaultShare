"""分享卡片：把接收方需要的公开信息装进一个小 JSON 文件。

卡片内容全部是公开信息（服务器地址、包 ID、发送方/代理指纹），可选附带
**口令**。附带口令时卡片本身就是取件凭证，必须按敏感文件保管并走安全渠道。

卡片**不是**信任锚：发送方指纹仍应通过与口令不同的可信渠道核对。卡片只是
减少手工输入，保存前会尽量收紧文件权限。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ..errors import ValidationError
from ..storage import permissions
from ..storage.atomic import atomic_write_bytes
from ..util.base32c import format_code, normalize_code
from ..util.canonical import canonical_bytes
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..util.serverurl import normalize_server_url
from ..util.timeutil import now
from ..version import PROTOCOL_VERSION

__all__ = [
    "SHARE_CARD_FORMAT",
    "ShareCard",
    "build_card",
    "load_card",
    "write_card",
    "card_bytes",
]

SHARE_CARD_FORMAT = "vaultshare-share-card"


def _fingerprint(value: str, field: str) -> str:
    text = (value or "").strip().lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValidationError(f"{field} 必须是 64 位十六进制 SHA-256")
    return text


@dataclass(frozen=True)
class ShareCard:
    package_id: str
    server: str
    sender_fingerprint: str
    broker_fingerprint: str
    code: str | None
    created_at: int

    def record(self) -> dict:
        return {
            "format": SHARE_CARD_FORMAT,
            "version": PROTOCOL_VERSION,
            "package_id": self.package_id,
            "server": self.server,
            "sender_fingerprint": self.sender_fingerprint,
            "broker_fingerprint": self.broker_fingerprint,
            "code": self.code,
            "created_at": self.created_at,
        }


def build_card(
    *,
    package_id: str,
    server: str,
    sender_fingerprint: str,
    broker_fingerprint: str,
    code: str | None = None,
    created_at: int | None = None,
) -> ShareCard:
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    normalized_code = None
    if code:
        try:
            normalized_code = format_code(normalize_code(code))
        except (ValueError, TypeError) as exc:
            raise ValidationError("口令格式非法") from exc
    return ShareCard(
        package_id=package_id.lower(),
        server=normalize_server_url(server),
        sender_fingerprint=_fingerprint(sender_fingerprint, "发送方指纹"),
        broker_fingerprint=_fingerprint(broker_fingerprint, "代理指纹"),
        code=normalized_code,
        created_at=int(created_at if created_at is not None else now()),
    )


def card_bytes(card: ShareCard) -> bytes:
    return canonical_bytes(card.record())


def write_card(path: str | os.PathLike, card: ShareCard) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(str(target), card_bytes(card))
    permissions.tighten(str(target))


def load_card(path: str | os.PathLike) -> ShareCard:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ValidationError(f"无法读取分享卡片：{exc}") from exc
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("分享卡片不是合法 JSON") from exc
    if not isinstance(record, dict):
        raise ValidationError("分享卡片结构非法")
    if record.get("format") != SHARE_CARD_FORMAT:
        raise ValidationError("不是 VaultShare 分享卡片")
    if record.get("version") != PROTOCOL_VERSION:
        raise ValidationError("不支持的分享卡片版本")
    return build_card(
        package_id=str(record.get("package_id") or ""),
        server=str(record.get("server") or ""),
        sender_fingerprint=str(record.get("sender_fingerprint") or ""),
        broker_fingerprint=str(record.get("broker_fingerprint") or ""),
        code=record.get("code") or None,
        created_at=int(record.get("created_at") or now()),
    )
