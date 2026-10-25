"""服务器地址的规范化与校验。

服务器地址会写进容器头部与分享卡片，属于**提示信息**，不是信任锚：接收方
仍然必须核对发送方/代理指纹。这里只做防呆与长度限制，避免把控制字符、
账号密码、查询串等写入头部。
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..errors import ValidationError

__all__ = ["MAX_SERVER_URL_BYTES", "normalize_server_url"]

MAX_SERVER_URL_BYTES = 512


def normalize_server_url(value: str | None) -> str:
    """返回去掉结尾斜杠的地址；空字符串表示“未记录”。"""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError("服务器地址必须是字符串")
    text = value.strip()
    if not text:
        return ""
    if len(text.encode("utf-8")) > MAX_SERVER_URL_BYTES:
        raise ValidationError("服务器地址过长")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValidationError("服务器地址包含控制字符")
    if "\\" in text or " " in text:
        raise ValidationError("服务器地址格式非法")
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise ValidationError("服务器地址格式非法") from exc
    if parts.scheme not in ("http", "https"):
        raise ValidationError("服务器地址必须以 http:// 或 https:// 开头")
    if not parts.hostname:
        raise ValidationError("服务器地址缺少主机名")
    if parts.username is not None or parts.password is not None:
        raise ValidationError("服务器地址不能包含账号或密码")
    if parts.query or parts.fragment:
        raise ValidationError("服务器地址不能包含查询串或片段")
    normalized = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
    if len(normalized.encode("utf-8")) > MAX_SERVER_URL_BYTES:
        raise ValidationError("服务器地址过长")
    return normalized
