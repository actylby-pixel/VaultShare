"""网页管理界面、子路径部署与网页上传（显式开启）的集成测试。"""

from __future__ import annotations

import contextlib
import io
import shutil
import socket
import sys
import time
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_settings, write_source_tree  # noqa: E402

import pyotp  # noqa: E402

from vaultshare.broker.ipc import IpcServer  # noqa: E402
from vaultshare.broker.service import SoftwareKeyBroker  # noqa: E402
from vaultshare.client.codes import open_sealed_code  # noqa: E402
from vaultshare.client.identity import create_identity  # noqa: E402
from vaultshare.client.pack import encrypt_package  # noqa: E402
from vaultshare.server.app import create_app  # noqa: E402
from vaultshare.server.auth import CredentialsStore  # noqa: E402
from vaultshare.storage.package_store import payload_path  # noqa: E402
from vaultshare.storage.secrets import read_ipc_key  # noqa: E402
from vaultshare.util.canonical import sha256_hex  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _AppCase(unittest.TestCase):
    url_prefix = ""
    web_upload = False

    def setUp(self) -> None:
        base, self.root = make_settings("vaultshare-webui-")
        self.settings = replace(
            base,
            broker_port=_free_port(),
            url_prefix=self.url_prefix,
            web_upload=self.web_upload,
        )
        self.settings.ensure_dirs()
        self.stdout = io.StringIO()
        with contextlib.redirect_stdout(self.stdout):
            self.app = create_app(self.settings, acquire_writer=False)
        self.initial = self.app.extensions["vaultshare_initial_credentials"]
        self.creds = CredentialsStore(self.settings).load()
        self.context = self.app.extensions["vaultshare"]
        self.client = self.app.test_client()
        self.broker_server = None

    def tearDown(self) -> None:
        if self.broker_server is not None:
            self.broker_server.shutdown()
        self.app.extensions["vaultshare_shutdown"]()
        shutil.rmtree(self.root, ignore_errors=True)

    # ------------------------------------------------------------ 工具
    def _start_broker(self) -> None:
        self.broker_server = IpcServer(
            self.settings.broker_host,
            self.settings.broker_port,
            read_ipc_key(self.settings),
            SoftwareKeyBroker(self.settings).dispatch,
        )
        self.broker_server.start_background()
        time.sleep(0.2)

    def _totp(self) -> str:
        return pyotp.TOTP(self.creds.totp_secret).now()

    def _login(self, client=None, prefix: str = "", **kwargs) -> None:
        client = client or self.client
        client.get(f"{prefix}/login", **kwargs)
        with client.session_transaction() as sess:
            csrf = sess["pre_csrf"]
        response = client.post(
            f"{prefix}/login",
            data={
                "csrf_token": csrf,
                "username": self.creds.username,
                "password": self.initial.password,
                "totp": self._totp(),
            },
            **kwargs,
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))

    def _csrf(self, client=None) -> str:
        client = client or self.client
        with client.session_transaction() as sess:
            sid = sess["sid"]
        current = self.context.sessions.get(sid)
        assert current is not None
        return current.csrf_token


class WebPagesTests(_AppCase):
    def test_local_delivery_package_is_not_counted_as_pending(self) -> None:
        from vaultshare.util.ids import new_hex_id

        package_id = new_hex_id(16)

        def mutate(body: dict) -> None:
            body["packages"][package_id] = {
                "status": "active",
                "created_at": 0,
                "keyconfig_sha256": "0" * 64,
                "policy_sha256": "0" * 64,
                "payload_sha256": "",
                "payload_size": 0,
                "payload_mode": "local",
                "broker_key_id": "",
                "sender_key_id": "",
                "sender_identity_hash": "",
            }
            body["grants_counters"][package_id] = {
                "issued": 0,
                "allocated_uses": 0,
                "used": 0,
            }

        self.context.store.transaction(mutate)
        self._login()
        listing = self.client.get("/packages").get_data(as_text=True)
        self.assertIn("本地交付", listing)
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("未传文件 0", home)

    def test_pages_render_and_nav_hides_upload_by_default(self) -> None:
        self._login()
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        body = home.get_data(as_text=True)
        self.assertIn("共享包概览", body)
        self.assertIn("网页上传未启用", body)
        self.assertNotIn('href="/upload"', body)

        for path, marker in (
            ("/packages", "共享包"),
            ("/senders", "发送方身份"),
            ("/audit", "审核日志"),
            ("/system", "系统状态"),
            ("/upload", "网页上传未启用"),
        ):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200, path)
            self.assertIn(marker, page.get_data(as_text=True), path)

    def test_system_page_shows_broker_unavailable_without_error(self) -> None:
        self._login()
        page = self.client.get("/system")
        self.assertEqual(page.status_code, 200)
        self.assertIn("不可用", page.get_data(as_text=True))

    def test_audit_page_shows_events(self) -> None:
        self._login()
        page = self.client.get("/audit?limit=50")
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("login_session", body)
        # 上限收敛到 1..2000，非法值不应 500。
        self.assertEqual(self.client.get("/audit?limit=abc").status_code, 200)
        self.assertEqual(self.client.get("/audit?limit=999999").status_code, 200)

    def test_add_grants_route_rejects_when_web_upload_disabled(self) -> None:
        from vaultshare.util.ids import new_hex_id

        package_id = new_hex_id(16)

        def mutate(body: dict) -> None:
            body["packages"][package_id] = {
                "status": "active",
                "created_at": 0,
                "payload_mode": "local",
                "sender_key_id": "",
                "sender_identity_hash": "",
            }

        self.context.store.transaction(mutate)
        self._login()
        response = self.client.post(
            f"/packages/{package_id}/grants",
            data={"csrf_token": self._csrf(), "codes": "1", "max_uses": "1",
                  "expires": "1h"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("未启用", response.get_data(as_text=True))

    def test_upload_route_rejects_when_disabled(self) -> None:
        self._login()
        response = self.client.post(
            "/upload",
            data={"csrf_token": self._csrf(), "identity_password": "x"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("未启用", response.get_data(as_text=True))
        self.assertFalse(self.context.store.snapshot()["body"]["packages"])


class UrlPrefixTests(_AppCase):
    url_prefix = "/vault"

    def test_direct_access_with_prefix(self) -> None:
        # 直接访问（不经过反向代理、也没有 X-Forwarded-Prefix）：路径里带前缀。
        direct = {"base_url": "http://localhost/"}
        page = self.client.get("/vault/login", **direct)
        self.assertEqual(page.status_code, 200)
        self.assertIn("/vault/static/app.css", page.get_data(as_text=True))

        # 不带前缀的根路径重定向到带前缀的登录页。
        redirect = self.client.get("/", **direct)
        self.assertEqual(redirect.status_code, 302)
        self.assertEqual(redirect.headers["Location"], "/vault/login")

        self._login(prefix="/vault", **direct)
        home = self.client.get("/vault/", **direct)
        self.assertEqual(home.status_code, 200)
        self.assertIn("共享包概览", home.get_data(as_text=True))

    def test_forwarded_prefix_header(self) -> None:
        page = self.client.get("/login", headers={"X-Forwarded-Prefix": "/vault"})
        self.assertEqual(page.status_code, 200)
        self.assertIn("/vault/static/app.css", page.get_data(as_text=True))

    def test_forwarded_prefix_with_path_not_stripped(self) -> None:
        # 代理设置了前缀头但没有从 PATH_INFO 里剥掉 /vault。
        page = self.client.get(
            "/vault/login",
            headers={"X-Forwarded-Prefix": "/vault"},
            base_url="http://localhost/",
        )
        self.assertEqual(page.status_code, 200)
        self.assertIn("/vault/static/app.css", page.get_data(as_text=True))


class WebUploadTests(_AppCase):
    web_upload = True

    def setUp(self) -> None:
        super().setUp()
        self._start_broker()
        self._login()
        self.identity_password = "upload-test-password"
        self.keys = create_identity(
            str(self.root / "sender"), password=self.identity_password
        )
        self.source = write_source_tree(self.root / "source")
        self.package_dir = self.root / "encrypted"
        self.info = encrypt_package(
            str(self.source),
            str(self.package_dir),
            self.keys,
            server_url="http://127.0.0.1:5000",
        )

    def _upload(
        self,
        *,
        codes: str = "2",
        max_uses: str = "2",
        include_identity=True,
        local_payload: bool = False,
        note: str = "",
        max_codes: str = "50",
        expires: str = "1d",
    ):
        def handle(path: Path):
            return (io.BytesIO(path.read_bytes()), path.name)

        data = {
            "csrf_token": self._csrf(),
            "identity_password": self.identity_password,
            "codes": codes,
            "max_uses": max_uses,
            "expires": expires,
            "max_codes": max_codes,
        }
        if note:
            data["note"] = note
        if local_payload:
            data["local_payload"] = "1"
        package_files = [
            handle(self.package_dir / "upload-key.json"),
            handle(self.package_dir / "package.json"),
        ]
        if not local_payload:
            package_files.insert(0, handle(self.package_dir / "payload.vspk"))
        if include_identity:
            identity_files = [
                handle(self.root / "sender.json"),
                handle(self.root / "sender.key"),
            ]
        else:
            identity_files = []
        data["package_files"] = package_files
        data["identity_files"] = identity_files
        return self.client.post("/upload", data=data, content_type="multipart/form-data")

    def test_upload_creates_package_and_shows_codes(self) -> None:
        response = self._upload()
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200, body)
        self.assertIn("上传完成", body)
        self.assertIn("明文口令只显示这一次", body)

        state = self.context.store.snapshot()["body"]
        package = state["packages"][self.info.package_id]
        self.assertEqual(package["payload_sha256"], self.info.payload_sha256)
        grants = [
            g for g in state["grants"].values()
            if g.get("package_id") == self.info.package_id
        ]
        self.assertEqual(len(grants), 2)
        self.assertTrue(all(g["max_uses"] == 2 for g in grants))
        # 页面显示的是格式化后的明文口令（共 4 组，最后一组 6 位）。
        for grant in grants:
            self.assertIn(grant["grant_id"], body)

        listing = self.client.get("/packages").get_data(as_text=True)
        self.assertIn(self.info.package_id, listing)
        detail = self.client.get(f"/packages/{self.info.package_id}").get_data(as_text=True)
        self.assertIn(self.info.payload_sha256, detail)

        audit = (self.settings.audit_path).read_text(encoding="utf-8")
        self.assertIn("web_upload", audit)
        # 明文口令绝不进入审计日志，也不进入状态文件。
        state_text = self.settings.state_path.read_text(encoding="utf-8")
        for grant in grants:
            opened = open_sealed_code(
                self.info.package_id,
                grant["grant_id"],
                grant["sealed_code"],
                self.keys.x25519_private,
                self.keys.identity.x25519_public,
            )
            self.assertNotIn(opened.code, audit)
            self.assertNotIn(opened.code, state_text)

    def test_upload_rejects_wrong_password_and_writes_nothing(self) -> None:
        def handle(path: Path):
            return (io.BytesIO(path.read_bytes()), path.name)

        response = self.client.post(
            "/upload",
            data={
                "csrf_token": self._csrf(),
                "identity_password": "wrong-password",
                "codes": "1",
                "max_uses": "1",
                "expires": "1d",
                "package_files": [
                    handle(self.package_dir / "payload.vspk"),
                    handle(self.package_dir / "upload-key.json"),
                    handle(self.package_dir / "package.json"),
                ],
                "identity_files": [
                    handle(self.root / "sender.json"),
                    handle(self.root / "sender.key"),
                ],
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("无法解密身份私钥", response.get_data(as_text=True))
        self.assertFalse(self.context.store.snapshot()["body"]["packages"])

    def test_upload_requires_identity_files(self) -> None:
        response = self._upload(include_identity=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn("身份", response.get_data(as_text=True))
        self.assertFalse(self.context.store.snapshot()["body"]["packages"])

    def test_upload_rejects_invalid_numbers(self) -> None:
        response = self._upload(codes="abc")
        self.assertEqual(response.status_code, 400)
        self.assertIn("整数", response.get_data(as_text=True))

    def test_reupload_same_package_is_idempotent(self) -> None:
        first = self._upload()
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        first_state = self.context.store.snapshot()["body"]
        first_payload_sha = first_state["packages"][self.info.package_id]["payload_sha256"]
        first_grants = sum(
            1 for g in first_state["grants"].values()
            if g.get("package_id") == self.info.package_id
        )

        second = self._upload()
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        state = self.context.store.snapshot()["body"]
        self.assertEqual(
            state["packages"][self.info.package_id]["payload_sha256"], first_payload_sha
        )
        grants = [
            g for g in state["grants"].values()
            if g.get("package_id") == self.info.package_id
        ]
        # 同一 batch_id 不会重复发码。
        self.assertEqual(len(grants), first_grants)

    def test_local_delivery_upload_never_stores_ciphertext(self) -> None:
        response = self._upload(local_payload=True)
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200, body)
        self.assertIn("密文未上传", body)
        self.assertIn("本地交付", body)

        state = self.context.store.snapshot()["body"]
        package = state["packages"][self.info.package_id]
        self.assertEqual(package["payload_mode"], "local")
        self.assertEqual(package["payload_sha256"], "")
        self.assertFalse(payload_path(self.settings, self.info.package_id).exists())

        grants = [
            g for g in state["grants"].values()
            if g.get("package_id") == self.info.package_id
        ]
        self.assertEqual(len(grants), 2)

        audit = self.settings.audit_path.read_text(encoding="utf-8")
        self.assertIn('"payload_mode": "local"', audit)

    def test_upload_form_offers_local_delivery(self) -> None:
        page = self.client.get("/upload").get_data(as_text=True)
        self.assertIn("本地交付", page)
        self.assertIn('name="local_payload"', page)

    def test_upload_cannot_switch_delivery_mode(self) -> None:
        first = self._upload()
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))

        second = self._upload(local_payload=True)
        self.assertEqual(second.status_code, 400)
        self.assertIn("交付方式", second.get_data(as_text=True))
        self.assertEqual(
            self.context.store.snapshot()["body"]["packages"][self.info.package_id][
                "payload_mode"
            ],
            "server",
        )

    def _notes(self) -> dict:
        import json

        path = self.settings.notes_path
        if not path.exists():
            return {"packages": {}, "grants": {}}
        return json.loads(path.read_text(encoding="utf-8"))

    def _identity_uploads(self, prefix: str = "sender"):
        def handle(path: Path):
            return (io.BytesIO(path.read_bytes()), path.name)

        return [
            handle(self.root / f"{prefix}.json"),
            handle(self.root / f"{prefix}.key"),
        ]

    def _add_grants(self, *, codes="1", max_uses="2", expires="1h", prefix="sender"):
        return self.client.post(
            f"/packages/{self.info.package_id}/grants",
            data={
                "csrf_token": self._csrf(),
                "identity_password": self.identity_password,
                "codes": codes,
                "max_uses": max_uses,
                "expires": expires,
                "identity_files": self._identity_uploads(prefix),
            },
            content_type="multipart/form-data",
        )

    def _package_grants(self) -> list[dict]:
        state = self.context.store.snapshot()["body"]
        return [
            g for g in state["grants"].values()
            if g.get("package_id") == self.info.package_id
        ]

    def test_upload_saves_package_note_and_shows_it(self) -> None:
        response = self._upload(note="给财务的季度报表")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn("给财务的季度报表", response.get_data(as_text=True))
        self.assertEqual(
            self._notes()["packages"][self.info.package_id], "给财务的季度报表"
        )

        listing = self.client.get("/packages").get_data(as_text=True)
        self.assertIn("给财务的季度报表", listing)
        detail = self.client.get(
            f"/packages/{self.info.package_id}"
        ).get_data(as_text=True)
        self.assertIn("给财务的季度报表", detail)
        self.assertIn("package_note_updated", self.settings.audit_path.read_text("utf-8"))

    def test_package_note_can_be_edited_and_cleared(self) -> None:
        self._upload()
        url = f"/packages/{self.info.package_id}/note"
        response = self.client.post(
            url, data={"csrf_token": self._csrf(), "note": "  新备注\r\n第二行  "}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self._notes()["packages"][self.info.package_id], "新备注\n第二行"
        )

        response = self.client.post(url, data={"csrf_token": self._csrf(), "note": ""})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(self.info.package_id, self._notes()["packages"])

    def test_package_note_length_is_limited(self) -> None:
        self._upload()
        response = self.client.post(
            f"/packages/{self.info.package_id}/note",
            data={"csrf_token": self._csrf(), "note": "x" * 501},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("500", response.get_data(as_text=True))

    def test_grant_notes_are_saved_in_bulk(self) -> None:
        self._upload()
        grants = self._package_grants()
        self.assertEqual(len(grants), 2)
        payload = {"csrf_token": self._csrf()}
        for index, grant in enumerate(grants):
            payload[f"note_{grant['grant_id']}"] = f"给同事 {index}"
        response = self.client.post(
            f"/packages/{self.info.package_id}/grants/notes", data=payload
        )
        self.assertEqual(response.status_code, 302)

        notes = self._notes()["grants"]
        for index, grant in enumerate(grants):
            self.assertEqual(notes[grant["grant_id"]], f"给同事 {index}")
        detail = self.client.get(
            f"/packages/{self.info.package_id}"
        ).get_data(as_text=True)
        self.assertIn("给同事 0", detail)
        self.assertIn("grant_notes_updated", self.settings.audit_path.read_text("utf-8"))

        # 空值表示删除备注。
        self.client.post(
            f"/packages/{self.info.package_id}/grants/notes",
            data={"csrf_token": self._csrf(), f"note_{grants[0]['grant_id']}": ""},
        )
        self.assertNotIn(grants[0]["grant_id"], self._notes()["grants"])

    def test_add_grants_from_package_page(self) -> None:
        first = self._upload(codes="2", max_uses="2", max_codes="5", expires="1d")
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        self.assertEqual(len(self._package_grants()), 2)

        response = self._add_grants(codes="2", max_uses="2", expires="1h")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200, body)
        self.assertIn("已新增口令", body)
        self.assertIn("明文口令只显示这一次", body)

        grants = self._package_grants()
        self.assertEqual(len(grants), 4)
        audit = self.settings.audit_path.read_text("utf-8")
        self.assertIn("web_grants_added", audit)
        # 明文口令不会写进状态或审计。
        state_text = self.settings.state_path.read_text("utf-8")
        for grant in grants:
            opened = open_sealed_code(
                self.info.package_id,
                grant["grant_id"],
                grant["sealed_code"],
                self.keys.x25519_private,
                self.keys.identity.x25519_public,
            )
            self.assertNotIn(opened.code, state_text)
            self.assertNotIn(opened.code, audit)

    def test_add_grants_rejects_when_policy_limit_reached(self) -> None:
        self._upload(codes="2", max_uses="2", max_codes="2", expires="1d")
        response = self._add_grants(codes="1", max_uses="2", expires="1h")
        self.assertEqual(response.status_code, 400)
        self.assertIn("上限", response.get_data(as_text=True))
        self.assertEqual(len(self._package_grants()), 2)

    def test_add_grants_rejects_other_sender_identity(self) -> None:
        self._upload(codes="2", max_codes="5", expires="1d")
        other = create_identity(
            str(self.root / "other"), password="other-password"
        )
        self.assertNotEqual(other.identity.digest, self.keys.identity.digest)
        response = self.client.post(
            f"/packages/{self.info.package_id}/grants",
            data={
                "csrf_token": self._csrf(),
                "identity_password": "other-password",
                "codes": "1",
                "max_uses": "2",
                "expires": "1h",
                "identity_files": self._identity_uploads("other"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("不一致", response.get_data(as_text=True))
        self.assertEqual(len(self._package_grants()), 2)

    def test_add_grants_rejects_revoked_package(self) -> None:
        self._upload(codes="1", max_codes="5", expires="1d")
        self.client.post(
            f"/packages/{self.info.package_id}/revoke",
            data={"csrf_token": self._csrf()},
        )
        response = self._add_grants(codes="1", max_uses="2", expires="1h")
        self.assertEqual(response.status_code, 400)
        self.assertIn("撤销", response.get_data(as_text=True))
        self.assertEqual(len(self._package_grants()), 1)

    def test_upload_nav_link_visible_when_enabled(self) -> None:
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('href="/upload"', body)
        page = self.client.get("/upload")
        self.assertEqual(page.status_code, 200)
        self.assertIn("发送方私钥口令", page.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
