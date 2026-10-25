"""发送方身份：Argon2id 加密的私钥文件、口令错误与篡改检测。"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from vaultshare.client.identity import create_identity, load_identity  # noqa: E402
from vaultshare.errors import ValidationError  # noqa: E402


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vaultshare-identity-"))
        self.prefix = str(self.root / "sender")
        self.password = "correct horse battery staple"

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_roundtrip(self) -> None:
        created = create_identity(self.prefix, password=self.password)
        self.assertTrue(Path(self.prefix + ".json").is_file())
        self.assertTrue(Path(self.prefix + ".key").is_file())

        loaded = load_identity(self.prefix, password=self.password)
        self.assertEqual(loaded.identity.digest, created.identity.digest)
        self.assertEqual(loaded.ed25519_private, created.ed25519_private)
        self.assertEqual(loaded.x25519_private, created.x25519_private)
        self.assertEqual(
            loaded.identity.record["ed25519_public_key"],
            created.identity.record["ed25519_public_key"],
        )
        # 私钥文件里不能出现明文私钥。
        raw = Path(self.prefix + ".key").read_bytes()
        self.assertNotIn(created.ed25519_private, raw)
        self.assertNotIn(created.x25519_private, raw)

    def test_wrong_password_rejected(self) -> None:
        create_identity(self.prefix, password=self.password)
        with self.assertRaises(ValidationError):
            load_identity(self.prefix, password="wrong")

    def test_tampered_ciphertext_rejected(self) -> None:
        created = create_identity(self.prefix, password=self.password)
        path = Path(self.prefix + ".key")
        record = json.loads(path.read_text(encoding="utf-8"))
        ciphertext = record["ciphertext"]
        record["ciphertext"] = ciphertext[:-4] + (
            "AAAA" if ciphertext[-4:] != "AAAA" else "BBBB"
        )
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(ValidationError):
            load_identity(self.prefix, password=self.password)
        self.assertGreater(len(created.identity.digest), 0)

    def test_public_record_tamper_rejected(self) -> None:
        create_identity(self.prefix, password=self.password)
        path = Path(self.prefix + ".json")
        record = json.loads(path.read_text(encoding="utf-8"))
        record["x25519_public_key"] = record["ed25519_public_key"]
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(ValidationError):
            load_identity(self.prefix, password=self.password)

    def test_key_file_requires_matching_public_record(self) -> None:
        first = create_identity(self.prefix, password=self.password)
        other = create_identity(str(self.root / "other"), password=self.password)
        self.assertNotEqual(first.identity.digest, other.identity.digest)
        # 用另一份身份的公钥记录覆盖，私钥就与记录不匹配。
        Path(self.prefix + ".json").write_bytes(
            Path(str(self.root / "other") + ".json").read_bytes()
        )
        with self.assertRaises(ValidationError):
            load_identity(self.prefix, password=self.password)


if __name__ == "__main__":
    unittest.main()
