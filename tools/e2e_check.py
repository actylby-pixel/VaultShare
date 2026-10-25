"""完整端到端验收脚本（不触碰真实 data/）。

流程：
    identity init → broker info（核对指纹）→ pack → 启动服务/代理
    → 登录 → 注册身份 → 创建包 → 上传 → 发码 → 解封口令
    → 兑换两次（同一口令，max_uses=2）→ 逐文件 SHA-256 比对
    → 同一 request_id 重放验证幂等与不重复扣次数
    → 撤销第二个口令并验证兑换被拒

运行（在仓库根目录）::

    .\\key\\Scripts\\python.exe ff\\tools\\e2e_check.py

脚本自行选择空闲端口，并在结束时清理临时目录（保留日志路径打印）。
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

from ff.vaultshare.broker.ipc import IpcClient, IpcServer
from ff.vaultshare.broker.service import SoftwareKeyBroker
from ff.vaultshare.client.codes import open_sealed_code
from ff.vaultshare.client.http import ApiError, HttpClient
from ff.vaultshare.client.identity import create_identity, load_identity
from ff.vaultshare.client.pack import load_broker_identity, pack_package
from ff.vaultshare.client.redeem import redeem_package
from ff.vaultshare.config import load_settings
from ff.vaultshare.protocol.identity import verify_broker_identity
from ff.vaultshare.protocol.redeem import build_redeem_request
from ff.vaultshare.server.app import create_app
from ff.vaultshare.storage.secrets import read_state_mac_key
from ff.vaultshare.storage.state import parse_envelope_bytes
from ff.vaultshare.util.canonical import canonical_bytes, sha256_hex


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tree_digest(root: Path) -> dict[str, str]:
    result = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            result[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def make_source(directory: Path) -> None:
    (directory / "子目录").mkdir(parents=True)
    (directory / "hello.txt").write_text("你好，VaultShare\n", encoding="utf-8")
    (directory / "子目录" / "data.bin").write_bytes(os.urandom(300_000))
    (directory / "empty.txt").write_bytes(b"")


def read_initial(settings) -> tuple[str, str, str]:
    text = settings.initial_credentials_path.read_text(encoding="utf-8")
    username = re.search(r"用户名:\s*(\S+)", text).group(1)
    password = re.search(r"密码:\s*(\S+)", text).group(1)
    uri = re.search(r"TOTP URI:\s*(\S+)", text).group(1)
    secret = uri.split("secret=")[1].split("&")[0]
    return username, password, secret


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="vaultshare-e2e-"))
    data = work / "data"
    os.environ["VAULTSHARE_DATA"] = str(data)
    os.environ["VAULTSHARE_BROKER_PORT"] = str(free_port())
    os.environ["VAULTSHARE_IDENTITY_PASSWORD"] = secrets.token_urlsafe(16)
    http_port = free_port()

    settings = load_settings()
    settings.ensure_dirs()
    app = create_app(settings)
    if app.extensions["vaultshare"].store.degraded:
        raise SystemExit("状态初始化失败")

    broker_service = SoftwareKeyBroker(settings)
    from ff.vaultshare.storage.secrets import read_ipc_key

    ipc = IpcServer(
        settings.broker_host,
        settings.broker_port,
        read_ipc_key(settings),
        broker_service.dispatch,
    )
    ipc.start_background()
    http_server = make_server("127.0.0.1", http_port, app, threaded=True)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    base = f"http://127.0.0.1:{http_port}"
    time.sleep(0.3)

    try:
        # 1. 身份与代理指纹
        sender_prefix = str(work / "sender")
        keys = create_identity(sender_prefix)
        client = HttpClient(base)
        record = client.get("/api/v1/broker")["identity"]
        broker_identity = verify_broker_identity(record)
        broker_path = work / "broker-identity.json"
        broker_path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        loaded = load_broker_identity(str(broker_path), broker_identity.fingerprint)
        print(f"[1] 代理指纹 {loaded.fingerprint[:16]}… 已核对")

        # 2. 打包
        src = work / "源目录"
        make_source(src)
        pack_dir = work / "pkg"
        info = pack_package(
            str(src), str(pack_dir), keys, loaded, codes=2, max_uses=3, expires="1d"
        )
        print(f"[2] 打包完成 package_id={info.package_id} 文件={info.manifest_files}")

        # 3. 登录并上传
        username, password, secret = read_initial(settings)
        login = client.post(
            "/api/v1/login",
            {"username": username, "password": password, "totp": pyotp.TOTP(secret).now()},
        )
        client.token = login["token"]
        client.post("/api/v1/identity", keys.identity.record)
        bundle = json.loads((pack_dir / "package.json").read_text(encoding="utf-8"))
        keyconfig = json.loads((pack_dir / "keyconfig.json").read_text(encoding="utf-8"))
        policy = json.loads((pack_dir / "policy.json").read_text(encoding="utf-8"))
        client.post("/api/v1/packages", {"keyconfig": keyconfig, "policy": policy})
        payload = pack_dir / "payload.vspk"
        payload_sha = sha256_hex(payload.read_bytes())
        client.put_file(
            f"/api/v1/packages/{info.package_id}/blob",
            str(payload),
            payload_sha,
            payload.stat().st_size,
        )
        batch = sha256_hex(b"vaultshare/batch/" + info.package_id.encode("ascii"))[:32]
        client.post(
            f"/api/v1/packages/{info.package_id}/grants",
            {
                "count": 2,
                "uses_per_code": 3,
                "expires_at": int(bundle["expires_at"]),
                "batch_id": batch,
            },
        )
        codes_raw = client.get(f"/api/v1/packages/{info.package_id}/codes")["grants"]
        codes = [
            open_sealed_code(
                info.package_id,
                grant["grant_id"],
                grant["sealed_code"],
                keys.x25519_private,
                keys.identity.x25519_public,
            ).code
            for grant in codes_raw
        ]
        assert len(codes) == 2 and all(codes), "口令生成失败"
        print("[3] 上传、发码与本地解封成功")

        # 4. 兑换两次（同一口令）
        expected = tree_digest(src)
        for attempt in (1, 2):
            out = work / f"out{attempt}"
            result = redeem_package(
                HttpClient(base),
                info.package_id,
                codes[0],
                str(out),
                sender_fingerprint=keys.identity.digest,
                broker_fingerprint=broker_identity.fingerprint,
            )
            actual = tree_digest(out)
            assert actual == expected, f"第 {attempt} 次解密内容不一致"
            print(f"[4.{attempt}] 兑换成功，文件摘要一致（{len(actual)} 个文件）")

        # 5. 同一 request_id 重放：字节一致且不重复扣次数
        outer, _ = build_redeem_request(
            package_id=info.package_id,
            broker_hpke_public=broker_identity.hpke_public,
            code=codes[0],
            recipient_public_key=_recipient_public(),
        )
        first = client.post("/api/v1/redeem", outer)
        second = client.post("/api/v1/redeem", outer)
        assert canonical_bytes(first["envelope"]) == canonical_bytes(second["envelope"])
        assert second["replayed"] is True
        print("[5] request_id 重放返回同一信封且标记 replayed")

        # 6. 撤销第二个口令并验证拒绝
        second_grant = codes_raw[1]["grant_id"]
        client.post(f"/api/v1/grants/{second_grant}/revoke")
        try:
            redeem_package(
                HttpClient(base),
                info.package_id,
                codes[1],
                str(work / "out-revoked"),
                sender_fingerprint=keys.identity.digest,
                broker_fingerprint=broker_identity.fingerprint,
            )
        except (ApiError, Exception) as exc:  # noqa: BLE001
            print(f"[6] 已撤销口令被拒绝：{type(exc).__name__}")
        else:
            raise AssertionError("已撤销口令仍可兑换")

        # 7. 状态与额度：used 恰好 3（两次正常 + 一次重放命中缓存不再扣）
        env = parse_envelope_bytes(
            read_state_mac_key(settings), settings.state_path.read_bytes()
        )
        used = sum(
            g["used"]
            for g in env["body"]["grants"].values()
            if g["package_id"] == info.package_id
        )
        assert used == 3, f"额度计数错误：{used}"
        print(f"[7] 状态消费次数 = {used}（重放未重复扣减）")
        print("\nE2E 全部通过。")
        return 0
    finally:
        http_server.shutdown()
        ipc.shutdown()
        app.extensions["vaultshare_shutdown"]()
        if os.environ.get("VAULTSHARE_KEEP_E2E") != "1":
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"保留临时目录：{work}")


def _recipient_public() -> bytes:
    from ff.vaultshare.crypto.keys import x25519_generate

    _private, public = x25519_generate()
    return public


if __name__ == "__main__":
    raise SystemExit(main())
