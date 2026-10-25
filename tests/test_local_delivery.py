"""本地交付（payload_mode=local）：服务器只保存元数据与口令，不接收密文。"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import Env, make_sender, tree_digest  # noqa: E402

from vaultshare.client.redeem import redeem_package  # noqa: E402
from vaultshare.crypto import hpke  # noqa: E402
from vaultshare.errors import ValidationError  # noqa: E402
from vaultshare.protocol.container import unpack_container  # noqa: E402
from vaultshare.protocol.envelope import open_envelope  # noqa: E402
from vaultshare.protocol.keyconfig import build_keyconfig  # noqa: E402
from vaultshare.protocol.policy import build_policy, policy_digest  # noqa: E402
from vaultshare.protocol.redeem import build_redeem_request  # noqa: E402
from vaultshare.server.app import create_app  # noqa: E402
from vaultshare.server.auth import issue_bearer  # noqa: E402
from vaultshare.server.package_checks import load_package_context  # noqa: E402
from vaultshare.server.redeem_flow import redeem  # noqa: E402
from vaultshare.storage.package_store import payload_path  # noqa: E402
from vaultshare.util.ids import new_hex_id  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402


def _make_local(env: Env, package) -> Path:
    """把已创建的包改成“本地交付”，把容器挪到服务器目录之外。"""
    container = env.root / "交付给接收方" / "payload.vspk"
    container.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(payload_path(env.settings, package.package_id)), str(container))
    package_id = package.package_id

    def mutate(body: dict) -> None:
        record = body["packages"][package_id]
        record["payload_mode"] = "local"
        record["payload_sha256"] = ""
        record["payload_size"] = 0

    env.store.transaction(mutate)
    assert not payload_path(env.settings, package_id).exists()
    return container


def _materials(env: Env, package, *, mode: str) -> dict:
    snapshot = env.store.snapshot()["body"]
    record = snapshot["packages"][package.package_id]
    return {
        "package_id": package.package_id,
        "keyconfig": package.keyconfig,
        "policy": package.policy,
        "sender_identity": package.sender.identity.record,
        "broker_identity": env.broker_identity.record,
        "status": record["status"],
        "payload_sha256": record.get("payload_sha256", ""),
        "payload_size": record.get("payload_size", 0),
        "payload_mode": mode,
    }


class _FakeClient:
    """只实现 redeem_package 用到的三个方法，并记录是否试图下载密文。"""

    def __init__(self, env: Env, materials: dict) -> None:
        self.env = env
        self.materials = materials
        self.calls: list[tuple[str, str]] = []

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path.endswith("/public"):
            return self.materials
        raise AssertionError(f"意外的请求：{path}")

    def post(self, path: str, body: dict) -> dict:
        self.calls.append(("POST", path))
        if path != "/api/v1/redeem":
            raise AssertionError(f"意外的请求：{path}")
        outcome = redeem(self.env.context, body)
        return {"request_id": body["request_id"], "envelope": outcome.envelope}

    def download(self, path: str, dest: str) -> int:
        raise AssertionError(f"本地交付不应下载密文：{path}")


class LocalDeliveryServerTests(unittest.TestCase):
    """服务器侧：本地交付的包可以签发口令、可以兑换，但拒绝收发密文。"""

    def setUp(self) -> None:
        self.env = Env("vaultshare-local-server-")
        self.sender = make_sender()

    def tearDown(self) -> None:
        self.env.close()

    def test_local_package_needs_no_payload_for_checks_or_redemption(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        container = _make_local(self.env, package)

        body = self.env.store.snapshot()["body"]
        ctx = load_package_context(
            self.env.settings, body, package.package_id, require_payload=True
        )
        self.assertEqual(ctx.package["payload_mode"], "local")

        # 兑换本身不依赖服务器上的密文；密钥仍然能解开本地容器。
        recipient_private, recipient_public = hpke.generate_keypair()
        outer, _inner = build_redeem_request(
            package_id=package.package_id,
            broker_hpke_public=self.env.broker_identity.hpke_public,
            code=package.first_code,
            recipient_public_key=recipient_public,
        )
        outcome = redeem(self.env.context, outer)
        core = outcome.envelope["envelope_core"]
        k_pkg = open_envelope(
            outcome.envelope,
            recipient_private_key=recipient_private,
            broker_signing_public=self.env.broker_identity.signing_public,
            package_id=package.package_id,
            grant_id=core["grant_id"],
            request_id=outer["request_id"],
            config_version=1,
            broker_key_id=self.env.keys.key_id,
        )
        staging = self.env.root / "local-unpacked"
        manifest = unpack_container(str(container), str(staging), k_pkg, package.package_id)
        self.assertEqual(manifest["total_files"], 3)
        self.assertTrue((staging / "hello.txt").is_file())

    def test_server_mode_still_requires_uploaded_payload(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        payload_path(self.env.settings, package.package_id).unlink()

        def clear(body: dict) -> None:
            record = body["packages"][package.package_id]
            record["payload_sha256"] = ""
            record["payload_size"] = 0

        self.env.store.transaction(clear)
        with self.assertRaises(ValidationError) as ctx:
            load_package_context(
                self.env.settings,
                self.env.store.snapshot()["body"],
                package.package_id,
                require_payload=True,
            )
        self.assertEqual(ctx.exception.code, "payload_missing")


class LocalDeliveryApiTests(unittest.TestCase):
    """API 侧：payload_mode 落盘与公开字段，以及 blob 接口的拒绝/404。"""

    def setUp(self) -> None:
        self.env = Env("vaultshare-local-api-")
        self.sender = make_sender()
        self.env.register_sender(self.sender)
        with contextlib.redirect_stdout(io.StringIO()):
            self.app = create_app(
                self.env.settings, acquire_writer=False, do_provision=False
            )
        self.context = self.app.extensions["vaultshare"]
        # 用进程内代理替换 IPC，接口语义保持一致。
        self.context.broker = self.env.fake_broker
        self.client = self.app.test_client()
        token, _expires = issue_bearer(
            self.context.secret,
            "admin",
            int(self.context.store.snapshot()["body"]["auth"].get("api_epoch", 1)),
        )
        self.auth = {"Authorization": f"Bearer {token}"}

    def tearDown(self) -> None:
        self.app.extensions["vaultshare_shutdown"]()
        self.env.close()

    def _package_payload(self, *, mode: str | None = None) -> dict:
        package_id = new_hex_id(16)
        created = now()
        policy = build_policy(
            package_id,
            self.sender.identity,
            self.sender.ed25519_private,
            max_codes=2,
            max_uses_per_code=2,
            max_total_redemptions=4,
            latest_expiry=created + 3600,
            created_at=created,
        )
        k_pkg = bytearray(os.urandom(32))
        try:
            keyconfig = build_keyconfig(
                package_id,
                policy_digest(policy),
                k_pkg,
                self.env.broker_identity,
                self.sender.identity,
                self.sender.ed25519_private,
                created_at=created,
            )
        finally:
            k_pkg[:] = b"\0" * 32
        body = {"keyconfig": keyconfig, "policy": policy}
        if mode is not None:
            body["payload_mode"] = mode
        return body

    def _create(self, **kwargs) -> str:
        response = self.client.post(
            "/api/v1/packages", json=self._package_payload(**kwargs), headers=self.auth
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()["package_id"]

    def test_local_mode_roundtrip_and_blob_rejection(self) -> None:
        package_id = self._create(mode="local")

        public = self.client.get(f"/api/v1/packages/{package_id}/public")
        self.assertEqual(public.status_code, 200)
        data = public.get_json()
        self.assertEqual(data["payload_mode"], "local")
        self.assertEqual(data["payload_sha256"], "")

        # 本地交付的包可以在没有密文的情况下签发口令。
        grants = self.client.post(
            f"/api/v1/packages/{package_id}/grants",
            json={"count": 1, "uses_per_code": 1, "expires_in": "1h"},
            headers=self.auth,
        )
        self.assertEqual(grants.status_code, 200, grants.get_data(as_text=True))
        self.assertEqual(len(grants.get_json()["grants"]), 1)

        blob = b"x" * 64
        put = self.client.put(
            f"/api/v1/packages/{package_id}/blob",
            data=blob,
            headers={
                **self.auth,
                "X-VaultShare-SHA256": hashlib.sha256(blob).hexdigest(),
                "X-VaultShare-Size": str(len(blob)),
            },
        )
        self.assertEqual(put.status_code, 409, put.get_data(as_text=True))
        self.assertFalse(payload_path(self.env.settings, package_id).exists())

        download = self.client.get(f"/api/v1/packages/{package_id}/blob")
        self.assertEqual(download.status_code, 404)
        self.assertFalse(payload_path(self.env.settings, package_id).exists())

    def test_server_mode_still_uploads(self) -> None:
        package_id = self._create()
        public = self.client.get(f"/api/v1/packages/{package_id}/public").get_json()
        self.assertEqual(public["payload_mode"], "server")

        blob = b"payload-bytes" * 10
        put = self.client.put(
            f"/api/v1/packages/{package_id}/blob",
            data=blob,
            headers={
                **self.auth,
                "X-VaultShare-SHA256": hashlib.sha256(blob).hexdigest(),
                "X-VaultShare-Size": str(len(blob)),
            },
        )
        self.assertEqual(put.status_code, 200, put.get_data(as_text=True))
        self.assertTrue(payload_path(self.env.settings, package_id).is_file())

        download = self.client.get(f"/api/v1/packages/{package_id}/blob")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, blob)
        download.close()

    def test_invalid_payload_mode_rejected(self) -> None:
        response = self.client.post(
            "/api/v1/packages",
            json=self._package_payload(mode="usb"),
            headers=self.auth,
        )
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))


class LocalDeliveryClientTests(unittest.TestCase):
    """客户端：本地容器直接解密，不再向服务器下载密文。"""

    def setUp(self) -> None:
        self.env = Env("vaultshare-local-client-")
        self.sender = make_sender()

    def tearDown(self) -> None:
        self.env.close()

    def _local_package(self):
        package = self.env.create_package(self.sender, codes=1, max_uses=2)
        container = _make_local(self.env, package)
        client = _FakeClient(self.env, _materials(self.env, package, mode="local"))
        source = self.env.root / f"src-{package.package_id[:8]}"
        return package, container, client, source

    def test_redeem_with_local_payload_does_not_download(self) -> None:
        package, container, client, source = self._local_package()
        out = self.env.root / "out-local"

        result = redeem_package(
            client,
            package.package_id,
            package.first_code,
            str(out),
            sender_fingerprint=package.sender.identity.digest,
            local_payload=str(container),
        )
        self.assertEqual(result.package_id, package.package_id)
        self.assertEqual(tree_digest(out), tree_digest(source))
        self.assertEqual([call[0] for call in client.calls], ["GET", "POST"])

    def test_local_package_without_container_fails_before_redeeming(self) -> None:
        package, _container, client, _source = self._local_package()
        with self.assertRaises(ValidationError) as ctx:
            redeem_package(
                client,
                package.package_id,
                package.first_code,
                str(self.env.root / "out-missing"),
                sender_fingerprint=None,
            )
        self.assertIn("本地交付", ctx.exception.message)
        # 没有提交兑换，因此没有消耗额度。
        self.assertEqual([call[0] for call in client.calls], ["GET"])
        grant = self.env.store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 0)

    def test_wrong_container_fails_before_redeeming(self) -> None:
        package, _container, client, _source = self._local_package()
        other = self.env.create_package(self.sender, codes=1, max_uses=1)
        other_container = payload_path(self.env.settings, other.package_id)
        with self.assertRaises(ValidationError) as ctx:
            redeem_package(
                client,
                package.package_id,
                package.first_code,
                str(self.env.root / "out-wrong"),
                sender_fingerprint=None,
                local_payload=str(other_container),
            )
        self.assertIn("package_id", ctx.exception.message)
        self.assertEqual([call[0] for call in client.calls], ["GET"])
        grant = self.env.store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 0)

    def test_server_package_can_also_use_local_container(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        client = _FakeClient(self.env, _materials(self.env, package, mode="server"))
        source = self.env.root / f"src-{package.package_id[:8]}"
        out = self.env.root / "out-server-local"

        redeem_package(
            client,
            package.package_id,
            package.first_code,
            str(out),
            sender_fingerprint=package.sender.identity.digest,
            local_payload=str(payload_path(self.env.settings, package.package_id)),
        )
        self.assertEqual(tree_digest(out), tree_digest(source))
        self.assertEqual([call[0] for call in client.calls], ["GET", "POST"])

    def test_tampered_container_is_rejected_by_hash(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        container = self.env.root / "modified.vspk"
        shutil.copyfile(payload_path(self.env.settings, package.package_id), container)
        with open(container, "r+b") as f:
            f.seek(-1, os.SEEK_END)
            last = f.read(1)
            f.seek(-1, os.SEEK_END)
            f.write(bytes([last[0] ^ 0xFF]))
        client = _FakeClient(self.env, _materials(self.env, package, mode="server"))
        with self.assertRaises(ValidationError) as ctx:
            redeem_package(
                client,
                package.package_id,
                package.first_code,
                str(self.env.root / "out-tampered"),
                sender_fingerprint=None,
                local_payload=str(container),
            )
        self.assertIn("SHA-256", ctx.exception.message)
        self.assertEqual([call[0] for call in client.calls], ["GET"])
        grant = self.env.store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 0)


if __name__ == "__main__":
    unittest.main()
