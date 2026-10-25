"""上传凭据：密封 K_pkg、签名与上下文绑定。"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_sender  # noqa: E402

from vaultshare.errors import ValidationError  # noqa: E402
from vaultshare.protocol.upload_key import (  # noqa: E402
    build_upload_key,
    open_upload_key,
    verify_upload_key,
)
from vaultshare.util.canonical import sha256_hex  # noqa: E402
from vaultshare.util.ids import PKG_ID_BYTES, new_hex_id  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402


class UploadKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = make_sender()
        self.package_id = new_hex_id(PKG_ID_BYTES)
        self.payload_sha = sha256_hex(b"payload")
        self.k_pkg = os.urandom(32)
        self.record = build_upload_key(
            package_id=self.package_id,
            server="http://127.0.0.1:5000/",
            payload_sha256=self.payload_sha,
            sender=self.keys.identity,
            signer_private=self.keys.ed25519_private,
            k_pkg=self.k_pkg,
            created_at=now(),
        )

    def test_roundtrip_and_server_normalization(self) -> None:
        parsed = verify_upload_key(self.record, identity=self.keys.identity)
        self.assertEqual(parsed.server, "http://127.0.0.1:5000")
        opened = open_upload_key(
            parsed, self.keys.x25519_private, self.keys.identity.x25519_public
        )
        self.assertEqual(bytes(opened), self.k_pkg)

    def test_tampered_server_or_payload_rejected(self) -> None:
        for field, value in (
            ("server", "http://evil.example"),
            ("payload_sha256", "0" * 64),
        ):
            record = dict(self.record)
            record[field] = value
            with self.assertRaises(ValidationError):
                verify_upload_key(record)

    def test_wrong_identity_rejected(self) -> None:
        other = make_sender()
        with self.assertRaises(ValidationError):
            verify_upload_key(self.record, identity=other.identity)

    def test_wrong_private_key_cannot_open(self) -> None:
        other = make_sender()
        parsed = verify_upload_key(self.record, identity=self.keys.identity)
        with self.assertRaises(ValidationError):
            open_upload_key(
                parsed, other.x25519_private, other.identity.x25519_public
            )


if __name__ == "__main__":
    unittest.main()
