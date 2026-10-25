"""GUI 动作层验收：只加密 → 上传时定策略 → 解密。

不创建 Qt 窗口，直接调用 ``vaultshare.gui.actions`` 与上传客户端；脚本自行选择
空闲端口、使用临时 ``VAULTSHARE_DATA``，结束时清理。运行（在 ``ff/`` 目录）::

    ..\\key\\Scripts\\python.exe tools\\gui_flow_check.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ff"))

import pyotp
from werkzeug.serving import make_server

from ff.vaultshare.broker.ipc import IpcServer
from ff.vaultshare.broker.service import SoftwareKeyBroker
from ff.vaultshare.client.http import HttpClient
from ff.vaultshare.client.identity import load_identity
from ff.vaultshare.client.share import ensure_share_ready, upload_package
from ff.vaultshare.config import load_settings
from ff.vaultshare.gui.actions import (
    DecryptInput,
    EncryptInput,
    load_source_hint,
    run_decrypt,
    run_encrypt,
)
from ff.vaultshare.protocol.identity import verify_broker_identity
from ff.vaultshare.server.app import create_app
from ff.vaultshare.storage.package_store import payload_path
from ff.vaultshare.storage.secrets import read_ipc_key


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tree_digest(root: Path) -> dict[str, str]:
    result = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            result[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return result


def make_source(directory: Path) -> None:
    (directory / "子目录").mkdir(parents=True)
    (directory / "hello.txt").write_text("你好，GUI\n", encoding="utf-8")
    (directory / "子目录" / "data.bin").write_bytes(os.urandom(200_000))


def read_initial(settings):
    text = settings.initial_credentials_path.read_text(encoding="utf-8")
    username = re.search(r"用户名:\s*(\S+)", text).group(1)
    password = re.search(r"密码:\s*(\S+)", text).group(1)
    uri = re.search(r"TOTP URI:\s*(\S+)", text).group(1)
    secret = uri.split("secret=")[1].split("&")[0]
    return username, password, secret


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="vaultshare-gui-flow-"))
    os.environ["VAULTSHARE_DATA"] = str(work / "data")
    os.environ["VAULTSHARE_BROKER_PORT"] = str(free_port())
    http_port = free_port()

    settings = load_settings()
    settings.ensure_dirs()
    app = create_app(settings)
    if app.extensions["vaultshare"].store.degraded:
        raise SystemExit("状态初始化失败")

    broker_service = SoftwareKeyBroker(settings)
    ipc = IpcServer(
        settings.broker_host,
        settings.broker_port,
        read_ipc_key(settings),
        broker_service.dispatch,
    )
    ipc.start_background()
    http_server = make_server("127.0.0.1", http_port, app, threaded=True)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{http_port}"
    time.sleep(0.3)

    try:
        username, password, secret = read_initial(settings)
        identity_password = secrets.token_urlsafe(16)
        sender_prefix = str(work / "sender")

        src = work / "源目录"
        make_source(src)
        pkg = work / "pkg"
        statuses: list[str] = []
        enc = run_encrypt(
            EncryptInput(
                server=base,
                source=str(src),
                output=str(pkg),
                identity_prefix=sender_prefix,
                identity_password=identity_password,
            ),
            status=statuses.append,
        )
        assert enc.upload_key_path and Path(enc.container_path).is_file(), enc
        assert not (pkg / "keyconfig.json").exists()
        print(f"[1] GUI 只加密完成 package={enc.package_id} 容器={enc.container_path}")
        print("    状态：" + " / ".join(statuses))

        hint = load_source_hint(enc.container_path)
        assert hint.server == base and hint.package_id == enc.package_id
        assert hint.require_sender_fingerprint is True
        print("[2] 容器头部内嵌服务器地址与指纹核对要求可读")

        keys = load_identity(sender_prefix, password=identity_password)
        broker_record = HttpClient(base).get("/api/v1/broker")["identity"]
        broker = verify_broker_identity(broker_record)
        bundle = ensure_share_ready(
            pkg,
            keys,
            broker,
            codes=2,
            max_uses=2,
            expires="1h",
            expected_server=base,
        )
        assert bundle.get("stage") == "share-ready"
        assert (pkg / "keyconfig.json").is_file() and (pkg / "policy.json").is_file()
        print(f"[3] 上传前按选择生成策略：codes={bundle['codes']} uses={bundle['max_uses']}")

        client = HttpClient(base)
        login = client.post(
            "/api/v1/login",
            {"username": username, "password": password, "totp": pyotp.TOTP(secret).now()},
        )
        client.token = login["token"]
        uploaded = upload_package(client, pkg, keys, payload_mode="local")
        assert len(uploaded.codes) == 2
        public = client.get(f"/api/v1/packages/{enc.package_id}/public")
        assert public.get("payload_mode") == "local"
        state = app.extensions["vaultshare"].store.snapshot()["body"]
        assert state["packages"][enc.package_id]["payload_sha256"] == ""
        assert not payload_path(settings, enc.package_id).exists()
        print(f"[4] 本地交付：只上传元数据，取得 {len(uploaded.codes)} 个口令（未传密文）")

        out = work / "解包"
        result = run_decrypt(
            DecryptInput(
                server="",
                package_id="",
                code=uploaded.codes[0].formatted,
                output=str(out),
                sender_fingerprint=enc.sender_fingerprint,
                container=enc.container_path,
            )
        )
        assert tree_digest(out) == tree_digest(src)
        assert result.package_id == enc.package_id
        print("[5] GUI 解密成功（服务器/package_id 全部来自容器），文件摘要一致")

        meta = json.loads(Path(enc.upload_key_path).read_text(encoding="utf-8"))
        assert "password" not in meta and "k_pkg" not in meta
        print("[6] 上传凭据只含密封密钥，无明文 K_pkg")
        print("\nGUI 全链路通过。")
        return 0
    finally:
        http_server.shutdown()
        ipc.shutdown()
        app.extensions["vaultshare_shutdown"]()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
