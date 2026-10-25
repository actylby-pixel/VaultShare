"""命令行客户端的 HTTP 封装（标准库 urllib）。

* 始终验证 TLS 证书；没有 ``--insecure`` 开关。
* 可以用 ``ca_file``（或环境变量 ``VAULTSHARE_CA_FILE``）指定**唯一信任的
  证书/CA 文件**：此时只信任该文件，不加载系统根证书，适合自签名部署。
* 打包成 exe（PyInstaller）时，随包携带的 ``qrlink.crt`` 会作为默认信任锚：
  优先级为 显式参数 > 环境变量 > 包内证书 > 系统根证书。
* 服务器错误体是 ``{"error": code, "message": ...}``，这里统一转成
  :class:`ApiError`，调用方只处理语义。
* 上传按流式发送，避免把整个容器读进内存。
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..version import __version__

__all__ = ["ApiError", "HttpClient"]

# exe 内部证书所在目录，必须与打包命令 --add-data "...;certs" 的右半部分一致
_BUNDLED_CA_SUBDIR = "certs"
_BUNDLED_CA_NAME = "qrlink.crt"


def _bundled_ca_file() -> str | None:
    """PyInstaller 包内随附的证书（仅冻结运行时生效）。

    开发环境不自动启用，避免本地跑脚本时悄悄换掉系统根证书。
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / _BUNDLED_CA_SUBDIR / _BUNDLED_CA_NAME
    return str(candidate) if candidate.is_file() else None


@dataclass(frozen=True)
class ApiError(Exception):
    status: int
    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - 展示用
        return f"[{self.status} {self.code}] {self.message}"


class HttpClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        timeout: float = 60.0,
        ca_file: str | None = None,
    ):
        base = base_url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise ValueError("server URL 必须以 http:// 或 https:// 开头")
        self.base = base
        self.token = token
        self.timeout = timeout

        explicit_ca = ca_file or os.environ.get("VAULTSHARE_CA_FILE")
        bundled_ca = _bundled_ca_file()
        self.ca_file = explicit_ca or bundled_ca or None

        # 冻结（exe）模式下必须能找到内置证书，否则直接失败，
        # 避免悄悄回退系统根证书后报 self-signed certificate 难以排查。
        if getattr(sys, "frozen", False) and not self.ca_file:
            raise RuntimeError(
                "exe 内未找到内置证书 "
                f"{_BUNDLED_CA_SUBDIR}/{_BUNDLED_CA_NAME}，"
                "请检查 --add-data 或 .spec 的 datas 是否把它打进包里"
            )

        self._context = None
        if self.ca_file:
            if not os.path.isfile(self.ca_file):
                # 显式指定的证书路径写错了，也直接失败，不要回退
                raise ValueError(f"CA 证书文件不存在：{self.ca_file}")
            # 指定 cafile 时只信任该文件，不再加载系统根证书。
            self._context = ssl.create_default_context(cafile=self.ca_file)

    # ------------------------------------------------------------ 内部
    def _headers(self, extra: dict | None = None) -> dict:
        headers = {
            "User-Agent": f"VaultShare-CLI/{__version__}",
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra:
            headers.update(extra)
        return headers

    def _url(self, path: str) -> str:
        return self.base + path

    def _request(self, method: str, path: str, *, data: bytes | None = None,
                 headers: dict | None = None) -> Any:
        request = urllib.request.Request(
            self._url(path), data=data, method=method, headers=self._headers(headers)
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._context
            ) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise ApiError(0, "network", f"无法连接服务器：{exc.reason}") from exc
        if not raw:
            if 200 <= status < 300:
                return None
            raise ApiError(status, "empty", f"服务器返回 {status} 且无响应体")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(status, "bad_response", "服务器响应不是 JSON") from exc
        if not 200 <= status < 300:
            code = str(payload.get("error") or "http_error")
            message = str(payload.get("message") or f"HTTP {status}")
            raise ApiError(status, code, message)
        return payload

    # ------------------------------------------------------------ 公开
    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def post(self, path: str, body: dict | None = None) -> dict:
        raw = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        return self._request(
            "POST", path, data=raw, headers={"Content-Type": "application/json"}
        )

    def download(self, path: str, dest: str) -> int:
        """把二进制响应流式写入 ``dest`` 并返回字节数。"""
        request = urllib.request.Request(self._url(path), method="GET",
                                        headers=self._headers({"Accept": "application/octet-stream"}))
        written = 0
        try:
            with urllib.request.urlopen(
                request, timeout=max(self.timeout, 300), context=self._context
            ) as response:
                with open(dest, "wb") as out:
                    for block in iter(lambda: response.read(1024 * 1024), b""):
                        written += len(block)
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001
                payload = {}
            raise ApiError(
                exc.code,
                str(payload.get("error") or "download_failed"),
                str(payload.get("message") or f"下载失败：HTTP {exc.code}"),
            ) from exc
        except urllib.error.URLError as exc:
            raise ApiError(0, "network", f"下载时无法连接服务器：{exc.reason}") from exc
        return written

    def put_file(self, path: str, file_path: str, sha256_hex: str, size: int) -> dict:
        length = os.path.getsize(file_path)
        if length != size:
            raise ValueError("文件大小在计算摘要后发生变化")
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(length),
            "X-VaultShare-SHA256": sha256_hex,
            "X-VaultShare-Size": str(length),
        }
        request = urllib.request.Request(
            self._url(path), method="PUT", headers=self._headers(headers)
        )
        try:
            with open(file_path, "rb") as payload:
                request.data = payload
                with urllib.request.urlopen(
                    request, timeout=max(self.timeout, 300), context=self._context
                ) as response:
                    raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            payload = {}
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001
                payload = {}
            raise ApiError(
                exc.code,
                str(payload.get("error") or "upload_failed"),
                str(payload.get("message") or f"上传失败：HTTP {exc.code}"),
            ) from exc
        except urllib.error.URLError as exc:
            raise ApiError(0, "network", f"上传时无法连接服务器：{exc.reason}") from exc
        return json.loads(raw.decode("utf-8")) if raw else {}