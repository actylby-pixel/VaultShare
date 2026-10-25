"""自描述分块流容器（crypto_secretstream_xchacha20poly1305）。

移植自 ``vault_app/crypto/stream.py`` 的低层封装，但 AAD 由调用方构造：
``AAD = header || msg_index_u32be || ct_len_u32be``。

与旧实现的共同点：
* 长度前缀在流内，读取边界不需要外部提示；
* 每条消息的 ``ct_len`` 进入 AAD，篡改长度字段会变成认证失败；
* ``ct_len`` 先验后读，避免 4 字节篡改逼出巨大内存分配；
* 最后一条实际消息携带 ``TAG_FINAL``，空输入产生一条空 FINAL 消息。
"""

from __future__ import annotations

from typing import Callable, BinaryIO, Iterable, Iterator

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)
from nacl.exceptions import CryptoError

__all__ = [
    "StreamError",
    "CHUNK",
    "ABYTES",
    "HEADERBYTES",
    "LEN_PREFIX",
    "MAX_CT_LEN",
    "TAG_MESSAGE",
    "TAG_FINAL",
    "read_exactly",
    "encrypt_chunks",
    "decrypt_chunks",
]

CHUNK = 4 * 1024 * 1024
ABYTES = crypto_secretstream_xchacha20poly1305_ABYTES  # 17
HEADERBYTES = crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24
LEN_PREFIX = 4
MAX_CT_LEN = min(CHUNK, crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) + ABYTES

TAG_MESSAGE = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_FINAL

# aad_for(header, msg_index, ct_len) -> bytes
AADBuilder = Callable[[bytes, int, int], bytes]


class StreamError(Exception):
    """流解密失败：截断、篡改或容器格式非法。"""


def read_exactly(src: BinaryIO, n: int) -> bytes:
    if n == 0:
        return b""
    parts = []
    remaining = n
    while remaining > 0:
        chunk = src.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    data = b"".join(parts)
    if len(data) != n:
        raise StreamError(f"密文被截断：还需要 {n - len(data)} 字节")
    return data


def read_at_most(src: BinaryIO, n: int) -> bytes:
    if n <= 0:
        return b""
    parts = []
    remaining = n
    while remaining > 0:
        chunk = src.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def encrypt_chunks(
    chunks: Iterable[bytes],
    dst: BinaryIO,
    key: bytes,
    header_prefix: bytes,
    aad_for: AADBuilder,
    progress: Callable[[int], None] | None = None,
) -> tuple[bytes, int]:
    """加密并返回 ``(完整 header, 明文字节数)``。

    调用方负责让 ``aad_for`` 使用完整的 header（即 ``header_prefix + stream header``）。
    """
    key = bytes(key)
    state = crypto_secretstream_xchacha20poly1305_state()
    stream_header = crypto_secretstream_xchacha20poly1305_init_push(state, key)
    header = bytes(header_prefix) + stream_header
    dst.write(header)

    iterator = iter(chunks)
    try:
        cur = bytes(next(iterator))
    except StopIteration:
        cur = b""

    written = 0
    msg_index = 0
    while True:
        try:
            nxt = bytes(next(iterator))
            is_last = False
        except StopIteration:
            nxt = b""
            is_last = True
        ct_len = len(cur) + ABYTES
        dst.write(ct_len.to_bytes(LEN_PREFIX, "big"))
        dst.write(
            crypto_secretstream_xchacha20poly1305_push(
                state,
                cur,
                aad_for(header, msg_index, ct_len),
                TAG_FINAL if is_last else TAG_MESSAGE,
            )
        )
        written += len(cur)
        if progress is not None and cur:
            progress(len(cur))
        if is_last:
            return header, written
        cur = nxt
        msg_index += 1


def decrypt_chunks(
    src: BinaryIO,
    key: bytes,
    header: bytes,
    aad_for: AADBuilder,
    progress: Callable[[int], None] | None = None,
) -> Iterator[bytes]:
    """读取消息直到 ``TAG_FINAL``。``header`` 必须与文件开头的容器头部一致。"""
    key = bytes(key)
    if len(header) < HEADERBYTES:
        raise StreamError("容器头部过短")
    state = crypto_secretstream_xchacha20poly1305_state()
    try:
        crypto_secretstream_xchacha20poly1305_init_pull(
            state, header[-HEADERBYTES:], key
        )
    except CryptoError as exc:
        raise StreamError("流头部解密失败") from exc

    msg_index = 0
    while True:
        prefix = src.read(LEN_PREFIX)
        if prefix == b"":
            raise StreamError("密文在出现 FINAL 之前结束（被截断）")
        if len(prefix) < LEN_PREFIX:
            raise StreamError("密文长度字段被截断")
        ct_len = int.from_bytes(prefix, "big")
        if not (ABYTES <= ct_len <= MAX_CT_LEN):
            raise StreamError(f"密文长度字段越界：{ct_len}")
        ct = read_exactly(src, ct_len)
        try:
            msg, tag = crypto_secretstream_xchacha20poly1305_pull(
                state, ct, aad_for(header, msg_index, ct_len)
            )
        except CryptoError as exc:
            raise StreamError("分块解密失败：密文被篡改或密钥不匹配") from exc

        if tag == TAG_FINAL:
            if src.read(1) != b"":
                raise StreamError("FINAL 之后仍有数据（格式错误）")
            if msg:
                if progress is not None:
                    progress(len(msg))
                yield msg
            return
        if tag != TAG_MESSAGE:
            raise StreamError(f"意外的消息标签：{tag}")
        if not msg:
            raise StreamError("出现空的非 FINAL 消息（格式错误）")
        if progress is not None:
            progress(len(msg))
        yield msg
        msg_index += 1
