"""TLS：指定 CA 文件时只信任该证书，不加载系统根证书。"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from vaultshare.client.http import ApiError, HttpClient  # noqa: E402


def _self_signed(directory: Path, name: str) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{name}.pem"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        body = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


class TlsPinningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vaultshare-tls-"))
        self.cert, self.key = _self_signed(self.root, "server")
        self.other_cert, _other_key = _self_signed(self.root, "other")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert), str(self.key))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"https://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        for path in self.root.iterdir():
            path.unlink(missing_ok=True)
        self.root.rmdir()

    def test_ca_file_trusts_only_that_certificate(self) -> None:
        client = HttpClient(self.url, ca_file=str(self.cert))
        self.assertEqual(client.get("/api/v1/health")["status"], "ok")

        # 另一张自签名证书不在信任范围内，即使系统根证书也不认它。
        with self.assertRaises(ApiError) as ctx:
            HttpClient(self.url, ca_file=str(self.other_cert)).get("/api/v1/health")
        self.assertEqual(ctx.exception.code, "network")
        self.assertIn("certificate", ctx.exception.message.lower())

    def test_without_ca_file_self_signed_is_rejected(self) -> None:
        with self.assertRaises(ApiError) as ctx:
            HttpClient(self.url).get("/api/v1/health")
        self.assertEqual(ctx.exception.code, "network")

    def test_environment_variable_is_honoured(self) -> None:
        with mock.patch.dict(os.environ, {"VAULTSHARE_CA_FILE": str(self.cert)}):
            self.assertEqual(
                HttpClient(self.url).get("/api/v1/health")["status"], "ok"
            )

    def test_missing_ca_file_is_a_clear_error(self) -> None:
        with self.assertRaises(ValueError):
            HttpClient(self.url, ca_file=str(self.root / "missing.pem"))

    def test_bundled_certificate_is_default_when_frozen(self) -> None:
        """exe 内置的 qrlink.crt 作为默认信任锚，接收方无需配置。"""
        bundle = Path(tempfile.mkdtemp(prefix="vaultshare-bundle-"))
        try:
            shutil.copy(self.cert, bundle / "qrlink.crt")
            env = {k: v for k, v in os.environ.items() if k != "VAULTSHARE_CA_FILE"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "_MEIPASS", str(bundle), create=True):
                    client = HttpClient(self.url)
                    self.assertEqual(client.ca_file, str(bundle / "qrlink.crt"))
                    self.assertEqual(
                        client.get("/api/v1/health")["status"], "ok"
                    )
                # 非冻结运行（普通脚本）不会自动加载，仍走系统根证书。
                with mock.patch.object(sys, "_MEIPASS", None, create=True):
                    with self.assertRaises(ApiError):
                        HttpClient(self.url).get("/api/v1/health")
        finally:
            shutil.rmtree(bundle, ignore_errors=True)

    def test_explicit_ca_file_wins_over_bundled(self) -> None:
        bundle = Path(tempfile.mkdtemp(prefix="vaultshare-bundle-"))
        try:
            shutil.copy(self.other_cert, bundle / "qrlink.crt")
            env = {k: v for k, v in os.environ.items() if k != "VAULTSHARE_CA_FILE"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "_MEIPASS", str(bundle), create=True):
                    self.assertEqual(
                        HttpClient(self.url, ca_file=str(self.cert))
                        .get("/api/v1/health")["status"],
                        "ok",
                    )
                    with self.assertRaises(ApiError):
                        HttpClient(self.url).get("/api/v1/health")
        finally:
            shutil.rmtree(bundle, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
