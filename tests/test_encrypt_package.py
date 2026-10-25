"""只加密流程：单文件输入、允许非空输出目录、拒绝覆盖已有产物。"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_sender  # noqa: E402

from vaultshare.client.pack import encrypt_package  # noqa: E402
from vaultshare.errors import ValidationError  # noqa: E402
from vaultshare.protocol.container import unpack_container  # noqa: E402
from vaultshare.protocol.upload_key import open_upload_key, verify_upload_key  # noqa: E402


class EncryptPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vaultshare-encrypt-"))
        self.keys = make_sender()

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _encrypt(self, source: Path, out: Path):
        return encrypt_package(
            str(source),
            str(out),
            self.keys,
            server_url="http://127.0.0.1:5000/",
        )

    def _open_upload_key(self, out: Path) -> bytes:
        record = json.loads((out / "upload-key.json").read_text(encoding="utf-8"))
        parsed = verify_upload_key(record, identity=self.keys.identity)
        return open_upload_key(
            parsed, self.keys.x25519_private, self.keys.identity.x25519_public
        )

    def test_single_file_into_non_empty_output(self) -> None:
        source = self.root / "报告.txt"
        payload = "单文件加密\n".encode("utf-8") + bytes(range(256)) * 64
        source.write_bytes(payload)

        out = self.root / "out"
        out.mkdir()
        (out / "其他文件.txt").write_text("不相关", encoding="utf-8")

        info = self._encrypt(source, out)
        self.assertEqual(info.manifest_files, 1)
        self.assertEqual(info.manifest_bytes, len(payload))
        self.assertTrue((out / "payload.vspk").is_file())
        self.assertTrue((out / "upload-key.json").is_file())
        self.assertTrue((out / "package.json").is_file())
        # 已有的无关文件必须保留
        self.assertTrue((out / "其他文件.txt").is_file())

        k_pkg = self._open_upload_key(out)
        staging = self.root / "stage"
        manifest = unpack_container(
            out / "payload.vspk", staging, k_pkg, info.package_id
        )
        self.assertEqual(manifest["entries"][0]["path"], "报告.txt")
        self.assertEqual((staging / "报告.txt").read_bytes(), payload)

    def test_existing_artifact_is_not_overwritten(self) -> None:
        source = self.root / "a.txt"
        source.write_text("a", encoding="utf-8")
        out = self.root / "out"
        out.mkdir()
        (out / "payload.vspk").write_bytes(b"old")

        with self.assertRaises(ValidationError):
            self._encrypt(source, out)
        self.assertEqual((out / "payload.vspk").read_bytes(), b"old")
        self.assertFalse((out / "upload-key.json").exists())
        self.assertFalse((out / "package.json").exists())

    def test_output_path_that_is_a_file_rejected(self) -> None:
        source = self.root / "a.txt"
        source.write_text("a", encoding="utf-8")
        out = self.root / "not-a-dir"
        out.write_text("x", encoding="utf-8")

        with self.assertRaises(ValidationError):
            self._encrypt(source, out)


if __name__ == "__main__":
    unittest.main()
