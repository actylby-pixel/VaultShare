"""Web 认证、TOTP 重放、锁定持久化、CSRF 与会话/Bearer 隔离。"""

from __future__ import annotations

import contextlib
import io
import shutil
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_sender, make_settings  # noqa: E402

import pyotp  # noqa: E402

from vaultshare.server.app import create_app  # noqa: E402
from vaultshare.server.auth import CredentialsStore  # noqa: E402
from vaultshare.server.provision import ack_init  # noqa: E402

_PASSWORD_ERROR = "用户名、密码或验证码错误"


class WebAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.root = make_settings("vaultshare-web-")
        self.stdout = io.StringIO()
        with contextlib.redirect_stdout(self.stdout):
            self.app = create_app(self.settings, acquire_writer=False)
        self.initial = self.app.extensions["vaultshare_initial_credentials"]
        self.creds = CredentialsStore(self.settings).load()
        self.context = self.app.extensions["vaultshare"]
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.app.extensions["vaultshare_shutdown"]()
        shutil.rmtree(self.root, ignore_errors=True)

    # ------------------------------------------------------------ 工具
    def _pre_csrf(self, client=None) -> str:
        client = client or self.client
        client.get("/login")
        with client.session_transaction() as sess:
            return sess["pre_csrf"]

    def _totp(self, offset: int = 0) -> str:
        return pyotp.TOTP(self.creds.totp_secret).at(time.time() + offset * 30)

    def _login_form(self, *, password=None, totp=None, username=None, csrf=None, client=None):
        client = client or self.client
        csrf = csrf if csrf is not None else self._pre_csrf(client)
        return client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": username if username is not None else self.creds.username,
                "password": password if password is not None else self.initial.password,
                "totp": totp if totp is not None else self._totp(),
            },
            follow_redirects=False,
        )

    def _logged_in_csrf(self) -> str:
        with self.client.session_transaction() as sess:
            sid = sess["sid"]
        session = self.context.sessions.get(sid)
        assert session is not None
        return session.csrf_token

    # ------------------------------------------------------------ 登录
    def test_login_success_sets_session_and_headers(self) -> None:
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        headers = page.headers
        self.assertIn("script-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

        response = self._login_form()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertIn("vaultshare_session", response.headers.get("Set-Cookie", ""))

        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn("共享包", home.get_data(as_text=True))

        # 登录成功轮换了 sid：cookie 里是一个全新的服务端会话。
        with self.client.session_transaction() as sess:
            self.assertIsNotNone(self.context.sessions.get(sess["sid"]))

    def test_login_failures_are_indistinguishable(self) -> None:
        good = self._totp()
        cases = [
            {"password": self.initial.password + "x", "totp": good},
            {"password": self.initial.password, "totp": "000000"},
            {"username": "nobody", "totp": good},
        ]
        for case in cases:
            response = self._login_form(**case)
            self.assertEqual(response.status_code, 401)
            self.assertIn(_PASSWORD_ERROR, response.get_data(as_text=True))
            with self.client.session_transaction() as sess:
                self.assertNotIn("sid", sess)

    def test_totp_replay_rejected(self) -> None:
        code = self._totp()
        first = self._login_form(totp=code)
        self.assertEqual(first.status_code, 302)

        second_client = self.app.test_client()
        second = self._login_form(totp=code, client=second_client)
        self.assertEqual(second.status_code, 401)
        self.assertIn("验证码已使用", second.get_data(as_text=True))
        with second_client.session_transaction() as sess:
            self.assertNotIn("sid", sess)
        # 状态里记录的是已使用的时间步。
        self.assertGreater(
            int(self.context.store.snapshot()["body"]["auth"]["last_totp_step"]), 0
        )

    def test_csrf_required_on_login_form(self) -> None:
        self._pre_csrf()  # 先取得带 Cookie 的会话
        wrong = self._login_form(csrf="not-the-token")
        self.assertEqual(wrong.status_code, 401)
        self.assertIn("页面已过期", wrong.get_data(as_text=True))

        self._pre_csrf()
        missing = self.client.post(
            "/login",
            data={
                "username": self.creds.username,
                "password": self.initial.password,
                "totp": self._totp(),
            },
        )
        self.assertEqual(missing.status_code, 401)
        with self.client.session_transaction() as sess:
            self.assertNotIn("sid", sess)

    def test_csrf_failure_without_cookie_says_so(self) -> None:
        # 从未打开登录页 → 请求里没有会话 Cookie，应给出可操作的提示，
        # 而不是含糊的“页面已过期”。
        response = self.client.post(
            "/login",
            data={
                "username": self.creds.username,
                "password": self.initial.password,
                "totp": self._totp(),
            },
        )
        self.assertEqual(response.status_code, 401)
        body = response.get_data(as_text=True)
        self.assertIn("没有发送会话 Cookie", body)
        self.assertNotIn("页面已过期", body)

    def test_csrf_failure_rotates_token_for_retry(self) -> None:
        self._pre_csrf()
        wrong = self._login_form(csrf="not-the-token")
        self.assertEqual(wrong.status_code, 401)
        with self.client.session_transaction() as sess:
            fresh = sess["pre_csrf"]
        self.assertNotEqual(fresh, "not-the-token")
        # 失败响应里换发的新 token 可以直接用于下一次提交。
        retry = self._login_form(csrf=fresh)
        self.assertEqual(retry.status_code, 302)

    def test_lockout_persists_across_app_restart(self) -> None:
        # 前 4 次失败只记录（第 4 次已写入锁定时间）；随后即使凭证正确也被拒。
        for _ in range(4):
            response = self._login_form(password="wrong-password")
            self.assertEqual(response.status_code, 401)
        # 第 5 次在密码校验前就被锁定。
        blocked = self._login_form()
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("过于频繁", blocked.get_data(as_text=True))

        lockouts = self.context.store.snapshot()["body"]["auth"]["lockouts"]
        self.assertTrue(lockouts)

        second_app = create_app(
            self.settings, acquire_writer=False, do_provision=False
        )
        try:
            client = second_app.test_client()
            csrf = self._pre_csrf(client)
            response = client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "username": self.creds.username,
                    "password": self.initial.password,
                    "totp": self._totp(),
                },
            )
            self.assertEqual(response.status_code, 403)
        finally:
            second_app.extensions["vaultshare_shutdown"]()

    def test_logout_invalidates_server_session(self) -> None:
        self.assertEqual(self._login_form().status_code, 302)
        csrf = self._logged_in_csrf()
        with self.client.session_transaction() as sess:
            sid = sess["sid"]

        response = self.client.post("/logout", data={"csrf_token": csrf})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.context.sessions.get(sid))
        # 未认证的 GET 页面被送回登录页。
        home = self.client.get("/")
        self.assertEqual(home.status_code, 302)
        self.assertIn("/login", home.headers["Location"])

    def test_logout_requires_csrf(self) -> None:
        self.assertEqual(self._login_form().status_code, 302)
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)
        with self.client.session_transaction() as sess:
            self.assertIn("sid", sess)

    def test_initial_credentials_not_printed_when_non_tty(self) -> None:
        # 测试进程的 stdout 不是 TTY：密码只能进受控的一次性文件。
        self.assertIsNotNone(self.initial)
        self.assertNotIn(self.initial.password, self.stdout.getvalue())
        path = self.settings.initial_credentials_path
        self.assertTrue(path.exists())
        self.assertIn(self.initial.password, path.read_text(encoding="utf-8"))
        self.assertIn(str(path), self.stdout.getvalue())

        self.assertTrue(ack_init(self.settings))
        self.assertFalse(path.exists())

    # ------------------------------------------------------------ API
    def test_api_rejects_cookie_authentication(self) -> None:
        self.assertEqual(self._login_form().status_code, 302)
        response = self.client.post("/api/v1/packages", json={})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "cookie_auth")

    def test_api_bearer_flow_and_epoch_invalidation(self) -> None:
        api = self.app.test_client()
        login = api.post(
            "/api/v1/login",
            json={
                "username": self.creds.username,
                "password": self.initial.password,
                "totp": self._totp(),
            },
        )
        self.assertEqual(login.status_code, 200, login.get_data(as_text=True))
        token = login.get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        sender = make_sender()
        identity = api.post(
            "/api/v1/identity", json=sender.identity.record, headers=headers
        )
        self.assertEqual(identity.status_code, 200, identity.get_data(as_text=True))
        self.assertEqual(
            identity.get_json()["identity"]["identity_hash"], sender.identity.digest
        )

        # 认证纪元变化后，旧 Bearer token 立即失效。
        def bump(body):
            body["auth"]["api_epoch"] = int(body["auth"].get("api_epoch", 1)) + 1

        self.context.store.transaction(bump)
        stale = api.post(
            "/api/v1/identity", json=sender.identity.record, headers=headers
        )
        self.assertEqual(stale.status_code, 401)
        self.assertEqual(stale.get_json()["error"], "unauthenticated")

        # 公开健康检查无需 Bearer；受保护端点没有 Bearer 时被拒。
        anonymous = api.get("/api/v1/health")
        self.assertEqual(anonymous.status_code, 200)

        bare = api.post("/api/v1/identity", json=sender.identity.record)
        self.assertEqual(bare.status_code, 401)

    def test_api_login_wrong_password(self) -> None:
        api = self.app.test_client()
        response = api.post(
            "/api/v1/login",
            json={
                "username": self.creds.username,
                "password": "wrong",
                "totp": self._totp(),
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "unauthenticated")


if __name__ == "__main__":
    unittest.main()
