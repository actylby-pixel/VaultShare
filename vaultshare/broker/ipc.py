"""本地 IPC：长度前缀 JSON + HMAC。

绑定地址**必须**是回环地址（启动时强制检查）。每条请求消息::

    {v, seq, ts, request_id, body_sha256, op, body, mac}

``mac = HMAC-SHA256(ipc_hmac_key, canonical({v,seq,ts,request_id,body_sha256,op,body}))``

（规范文档里写作 ``v||seq||ts||...||canonical(body)``；实现使用对具名对象做
canonical JSON，字段集合与顺序由 ``sort_keys`` 固定，避免长度歧义。）

校验：HMAC、时间戳 ±60 秒、``body_sha256`` 与 body 一致、同一 ``request_id``
不得携带不同内容。重放缓存以 ``(request_id, body_sha256, op)`` 为键；相同三元组
是安全重试，返回缓存的响应而不是执行两次。

响应消息不带 ``seq``，但带请求的 ``request_id``、``ok``、``code``、
``message``、``body`` 与 HMAC。客户端必须验签后才能使用。
"""

from __future__ import annotations

import ipaddress
import json
import socket
import socketserver
import threading
import time
from collections import OrderedDict
from typing import Callable

from ..errors import IpcError, VaultShareError
from ..util.canonical import canonical_bytes, hmac_sha256, sha256_hex
from ..util.ids import REQUEST_ID_BYTES, is_hex_id, new_hex_id

__all__ = ["IpcServer", "IpcClient", "is_loopback"]

MAX_MESSAGE = 4 * 1024 * 1024
MAX_SKEW = 60
REPLAY_TTL = 600
REPLAY_MAX = 4096


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


def _frame(sock: socket.socket, obj: dict) -> None:
    payload = canonical_bytes(obj)
    if len(payload) > MAX_MESSAGE:
        raise IpcError("IPC 消息过大")
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def _read_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise IpcError("IPC 连接提前关闭")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> dict | None:
    prefix = sock.recv(4)
    if not prefix:
        return None
    if len(prefix) < 4:
        prefix += _read_exact(sock, 4 - len(prefix))
    length = int.from_bytes(prefix, "big")
    if length <= 0 or length > MAX_MESSAGE:
        raise IpcError("IPC 帧长度非法")
    try:
        return json.loads(_read_exact(sock, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IpcError("IPC 帧不是合法 JSON") from exc


def _request_mac(key: bytes, message: dict) -> bytes:
    return hmac_sha256(
        key,
        canonical_bytes(
            {
                "v": message["v"],
                "seq": message["seq"],
                "ts": message["ts"],
                "request_id": message["request_id"],
                "body_sha256": message["body_sha256"],
                "op": message["op"],
                "body": message["body"],
            }
        ),
    )


def _response_mac(key: bytes, message: dict) -> bytes:
    return hmac_sha256(
        key,
        canonical_bytes(
            {
                "v": message["v"],
                "ts": message["ts"],
                "request_id": message["request_id"],
                "ok": message["ok"],
                "code": message["code"],
                "message": message["message"],
                "body": message["body"],
            }
        ),
    )


class _ReplayCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str, str], tuple[float, dict]] = OrderedDict()

    def check_and_get(self, key: tuple[str, str, str]) -> dict | None:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            age, response = entry
            if now - age > REPLAY_TTL:
                self._entries.pop(key, None)
                return None
            return response

    def remember(self, key: tuple[str, str, str], response: dict) -> None:
        with self._lock:
            self._entries[key] = (time.monotonic(), response)
            self._entries.move_to_end(key)
            while len(self._entries) > REPLAY_MAX:
                self._entries.popitem(last=False)

    def known_request_id(self, request_id: str, body_sha256: str) -> bool:
        with self._lock:
            for (rid, digest, _op) in self._entries:
                if rid == request_id and digest != body_sha256:
                    return True
        return False


class _Handler(socketserver.BaseRequestHandler):
    server: "IpcServer"

    def handle(self) -> None:  # noqa: D102
        self.request.settimeout(15)
        try:
            message = _recv_frame(self.request)
        except (IpcError, OSError):
            return
        if message is None:
            return
        response = self.server.handle_message(message)
        if response is not None:
            try:
                _frame(self.request, response)
            except (IpcError, OSError):
                pass


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class IpcServer:
    def __init__(self, host: str, port: int, key: bytes, dispatch: Callable[[str, dict, str, str], dict]):
        if not is_loopback(host):
            raise ValueError("代理 IPC 只允许绑定回环地址")
        self.host = host
        self.port = port
        self.key = bytes(key)
        self.dispatch = dispatch
        self._replay = _ReplayCache()
        self._server: _ThreadingServer | None = None
        self._thread: threading.Thread | None = None

    def _response(self, request_id: str, ok: bool, body: dict, code: str = "", message: str = "") -> dict:
        response = {
            "v": 1,
            "ts": int(time.time()),
            "request_id": request_id,
            "ok": ok,
            "code": code,
            "message": message,
            "body": body,
        }
        response["mac"] = _response_mac(self.key, response).hex()
        return response

    def handle_message(self, message) -> dict | None:
        if not isinstance(message, dict):
            return None
        request_id = message.get("request_id")
        if not isinstance(request_id, str) or not is_hex_id(request_id, REQUEST_ID_BYTES):
            return None
        if set(message.keys()) != {
            "v",
            "seq",
            "ts",
            "request_id",
            "body_sha256",
            "op",
            "body",
            "mac",
        }:
            return self._response(request_id, False, {}, "bad_message", "消息字段非法")
        if message.get("v") != 1:
            return self._response(request_id, False, {}, "bad_version", "IPC 版本不支持")
        if not isinstance(message.get("body"), dict) or not isinstance(message.get("op"), str):
            return self._response(request_id, False, {}, "bad_message", "body/op 非法")
        try:
            mac = bytes.fromhex(message["mac"])
        except (TypeError, ValueError):
            return self._response(request_id, False, {}, "bad_mac", "MAC 非法")
        import hmac as _hmac

        if not _hmac.compare_digest(mac, _request_mac(self.key, message)):
            return self._response(request_id, False, {}, "bad_mac", "MAC 校验失败")
        ts = message.get("ts")
        if not isinstance(ts, int) or abs(int(time.time()) - ts) > MAX_SKEW:
            return self._response(request_id, False, {}, "stale", "时间戳超出允许范围")
        digest = message.get("body_sha256")
        if not isinstance(digest, str) or digest != sha256_hex(canonical_bytes(message["body"])):
            return self._response(request_id, False, {}, "bad_digest", "body 摘要不一致")
        op = message["op"]
        cache_key = (request_id, digest, op)
        cached = self._replay.check_and_get(cache_key)
        if cached is not None:
            # 用新的时间戳与 MAC 重发，避免客户端因响应时间戳过期而拒绝；
            # 逻辑结果与第一次执行完全一致。
            return self._response(
                request_id,
                bool(cached.get("ok")),
                cached.get("body") or {},
                str(cached.get("code") or ""),
                str(cached.get("message") or ""),
            )
        if self._replay.known_request_id(request_id, digest):
            return self._response(
                request_id, False, {}, "request_id_reuse", "同一 request_id 携带了不同内容"
            )
        try:
            body = self.dispatch(op, message["body"], request_id, digest)
            response = self._response(request_id, True, body)
        except VaultShareError as exc:
            response = self._response(
                request_id, False, {}, exc.code, exc.message
            )
        except Exception as exc:  # noqa: BLE001 - 绝不把堆栈发给调用方
            response = self._response(
                request_id, False, {}, "internal", f"代理内部错误（{type(exc).__name__}）"
            )
        self._replay.remember(cache_key, response)
        return response

    def serve_forever(self) -> None:
        self._server = _ThreadingServer((self.host, self.port), _Handler)
        self._server.ipc = self  # type: ignore[attr-defined]
        # BaseRequestHandler.server 指向 socketserver 实例；把 IpcServer 挂上去。
        self._server.handle_message = self.handle_message  # type: ignore[attr-defined]
        self._server.serve_forever(poll_interval=0.2)

    def start_background(self) -> None:
        self._server = _ThreadingServer((self.host, self.port), _Handler)
        self._server.handle_message = self.handle_message  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


class IpcClient:
    def __init__(self, host: str, port: int, key: bytes, timeout: float = 15.0):
        self.host = host
        self.port = int(port)
        self.key = bytes(key)
        self.timeout = timeout
        self._seq = 0
        self._lock = threading.Lock()

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def call(self, op: str, body: dict, *, request_id: str | None = None) -> dict:
        request_id = request_id or new_hex_id(REQUEST_ID_BYTES)
        digest = sha256_hex(canonical_bytes(body))
        message = {
            "v": 1,
            "seq": self._next_seq(),
            "ts": int(time.time()),
            "request_id": request_id,
            "body_sha256": digest,
            "op": op,
            "body": body,
        }
        message["mac"] = _request_mac(self.key, message).hex()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                _frame(sock, message)
                response = _recv_frame(sock)
        except (OSError, IpcError) as exc:
            raise IpcError(f"无法连接密钥代理：{exc}") from exc
        if not isinstance(response, dict):
            raise IpcError("代理返回了空响应")
        if response.get("request_id") != request_id:
            raise IpcError("代理响应的 request_id 不匹配")
        if response.get("v") != 1:
            raise IpcError("代理响应版本非法")
        ts = response.get("ts")
        if not isinstance(ts, int) or abs(int(time.time()) - ts) > MAX_SKEW:
            raise IpcError("代理响应时间戳超出允许范围")
        try:
            mac = bytes.fromhex(response.get("mac", ""))
        except (TypeError, ValueError) as exc:
            raise IpcError("代理响应 MAC 非法") from exc
        import hmac as _hmac

        if not _hmac.compare_digest(mac, _response_mac(self.key, response)):
            raise IpcError("代理响应 MAC 校验失败")
        if not response.get("ok"):
            raise IpcError(
                str(response.get("message") or "代理拒绝请求"),
                code=str(response.get("code") or "broker_denied"),
            )
        body_out = response.get("body")
        if not isinstance(body_out, dict):
            raise IpcError("代理响应 body 非法")
        return body_out
