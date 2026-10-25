"""容器打包/解包与 Windows 路径安全。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import tree_digest, write_source_tree  # noqa: E402

from vaultshare.crypto.kdf import stream_key  # noqa: E402
from vaultshare.crypto.stream import encrypt_chunks  # noqa: E402
from vaultshare.errors import ValidationError  # noqa: E402
from vaultshare.protocol.container import (  # noqa: E402
    MANIFEST_FORMAT,
    make_aad,
    make_header_prefix,
    pack_directory,
    read_container_meta,
    unpack_container,
)
from vaultshare.util.canonical import canonical_bytes  # noqa: E402
from vaultshare.util.ids import PKG_ID_BYTES, new_hex_id  # noqa: E402
from vaultshare.version import (  # noqa: E402
    CONTAINER_MAGIC,
    CONTAINER_VERSION,
    CONTAINER_VERSION_V1,
    CONTAINER_VERSION_V2,
    PROTOCOL_VERSION,
    STREAM_SUITE_ID,
)


def _build_manifest(package_id: str, entries: list[dict], *, total_bytes=None, total_files=None):
    return {
        "format": MANIFEST_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "entries": entries,
        "total_files": (
            sum(1 for e in entries if e["type"] == "file")
            if total_files is None
            else total_files
        ),
        "total_bytes": (
            sum(e["size"] for e in entries) if total_bytes is None else total_bytes
        ),
    }


def _write_container(
    path: Path,
    package_id: str,
    k_pkg: bytes,
    manifest: dict,
    payloads: list[bytes],
    *,
    trailing: bytes = b"",
    server_url: str = "",
    version: int = CONTAINER_VERSION,
    require_sender_fingerprint: bool = True,
    flags: int | None = None,
) -> None:
    """按容器格式写入一个（可能恶意的）manifest + 数据。"""
    if version == CONTAINER_VERSION_V1:
        # v1 头部没有服务器地址字段。
        prefix = (
            CONTAINER_MAGIC
            + bytes([CONTAINER_VERSION_V1])
            + bytes.fromhex(package_id)
            + int(STREAM_SUITE_ID).to_bytes(2, "big")
        )
    elif version == CONTAINER_VERSION_V2:
        # v2 头部没有 flags 字段。
        url = server_url.encode("utf-8")
        prefix = (
            CONTAINER_MAGIC
            + bytes([CONTAINER_VERSION_V2])
            + bytes.fromhex(package_id)
            + int(STREAM_SUITE_ID).to_bytes(2, "big")
            + len(url).to_bytes(2, "big")
            + url
        )
    else:
        prefix = make_header_prefix(
            package_id,
            server_url,
            require_sender_fingerprint=require_sender_fingerprint,
        )
        if flags is not None:
            prefix = prefix[:23] + bytes([flags]) + prefix[24:]
    key = stream_key(k_pkg, bytes.fromhex(package_id))
    manifest_bytes = canonical_bytes(manifest)

    def chunks():
        yield len(manifest_bytes).to_bytes(4, "big") + manifest_bytes
        for payload in payloads:
            yield payload
        if trailing:
            yield trailing

    with open(path, "wb") as dst:
        encrypt_chunks(chunks(), dst, key, prefix, make_aad)


class ContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vaultshare-container-"))
        self.package_id = new_hex_id(PKG_ID_BYTES)
        self.k_pkg = os.urandom(32)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def test_pack_and_unpack_roundtrip(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        result = pack_directory(source, container, self.k_pkg, self.package_id)
        self.assertEqual(result.manifest["total_files"], 3)

        staging = self.root / "stage"
        manifest = unpack_container(container, staging, self.k_pkg, self.package_id)
        self.assertEqual(manifest["total_files"], 3)
        self.assertEqual(tree_digest(staging), tree_digest(source))

    def test_single_file_roundtrip(self) -> None:
        source = self.root / "报告.txt"
        payload = "单文件也能加密\n".encode("utf-8") + bytes(range(256)) * 100
        source.write_bytes(payload)
        container = self.root / "single.vspk"
        result = pack_directory(source, container, self.k_pkg, self.package_id)
        self.assertEqual(result.manifest["total_files"], 1)
        self.assertEqual(result.manifest["entries"][0]["path"], "报告.txt")

        staging = self.root / "stage"
        manifest = unpack_container(container, staging, self.k_pkg, self.package_id)
        self.assertEqual(manifest["total_files"], 1)
        self.assertEqual((staging / "报告.txt").read_bytes(), payload)

    def test_server_hint_embedded_and_still_decrypts(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(
            source,
            container,
            self.k_pkg,
            self.package_id,
            server_url="http://127.0.0.1:5000/",
        )
        with open(container, "rb") as f:
            meta = read_container_meta(f)
        self.assertEqual(meta.version, CONTAINER_VERSION)
        self.assertEqual(meta.package_id, self.package_id)
        self.assertEqual(meta.server_url, "http://127.0.0.1:5000")

        staging = self.root / "stage"
        manifest = unpack_container(container, staging, self.k_pkg, self.package_id)
        self.assertEqual(manifest["total_files"], 3)
        self.assertEqual(tree_digest(staging), tree_digest(source))

    def test_v1_container_is_still_readable(self) -> None:
        container = self.root / "legacy.vspk"
        manifest = _build_manifest(
            self.package_id,
            [{"path": "a.txt", "type": "file", "size": 5, "mime": "text/plain"}],
        )
        _write_container(
            container,
            self.package_id,
            self.k_pkg,
            manifest,
            [b"hello"],
            version=CONTAINER_VERSION_V1,
        )
        with open(container, "rb") as f:
            meta = read_container_meta(f)
        self.assertEqual(meta.version, CONTAINER_VERSION_V1)
        self.assertEqual(meta.server_url, "")

        staging = self.root / "legacy-stage"
        unpack_container(container, staging, self.k_pkg, self.package_id)
        self.assertEqual((staging / "a.txt").read_bytes(), b"hello")

    def test_v2_container_is_still_readable(self) -> None:
        container = self.root / "v2.vspk"
        manifest = _build_manifest(
            self.package_id,
            [{"path": "a.txt", "type": "file", "size": 5, "mime": "text/plain"}],
        )
        _write_container(
            container,
            self.package_id,
            self.k_pkg,
            manifest,
            [b"hello"],
            server_url="http://127.0.0.1:5000",
            version=CONTAINER_VERSION_V2,
        )
        with open(container, "rb") as f:
            meta = read_container_meta(f)
        self.assertEqual(meta.version, CONTAINER_VERSION_V2)
        self.assertEqual(meta.server_url, "http://127.0.0.1:5000")
        # v2 没有 flags 字段，保持旧行为：必须核对指纹。
        self.assertTrue(meta.require_sender_fingerprint)

        staging = self.root / "v2-stage"
        unpack_container(container, staging, self.k_pkg, self.package_id)
        self.assertEqual((staging / "a.txt").read_bytes(), b"hello")

    def test_fingerprint_requirement_flag_roundtrip(self) -> None:
        source = write_source_tree(self.root / "src")
        for required in (True, False):
            with self.subTest(required=required):
                container = self.root / f"flag-{required}.vspk"
                pack_directory(
                    source,
                    container,
                    self.k_pkg,
                    self.package_id,
                    server_url="http://127.0.0.1:5000",
                    require_sender_fingerprint=required,
                )
                with open(container, "rb") as f:
                    meta = read_container_meta(f)
                self.assertEqual(meta.version, CONTAINER_VERSION)
                self.assertEqual(meta.require_sender_fingerprint, required)
                # flag 在 AAD 覆盖范围内，仍能正常解密。
                staging = self.root / f"stage-{required}"
                unpack_container(container, staging, self.k_pkg, self.package_id)
                self.assertEqual(tree_digest(staging), tree_digest(source))

    def test_unknown_flag_bits_rejected(self) -> None:
        container = self.root / "bad-flag.vspk"
        manifest = _build_manifest(
            self.package_id,
            [{"path": "a.txt", "type": "file", "size": 5, "mime": "text/plain"}],
        )
        _write_container(
            container,
            self.package_id,
            self.k_pkg,
            manifest,
            [b"hello"],
            flags=0x80,
        )
        with open(container, "rb") as f:
            with self.assertRaises(ValidationError):
                read_container_meta(f)

    def test_invalid_server_url_rejected_at_pack(self) -> None:
        source = write_source_tree(self.root / "src")
        for bad in ("ftp://host", "http://user:pw@host", "http:///nohost", "http://host/?q=1"):
            with self.subTest(url=bad):
                with self.assertRaises(ValidationError):
                    pack_directory(
                        source,
                        self.root / "bad.vspk",
                        self.k_pkg,
                        self.package_id,
                        server_url=bad,
                    )

    def test_tampered_server_url_fails_authentication(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        url = "http://127.0.0.1:5000"
        pack_directory(
            source, container, self.k_pkg, self.package_id, server_url=url
        )
        raw = bytearray(container.read_bytes())
        prefix_len = len(make_header_prefix(self.package_id, url))
        url_start = prefix_len - len(url)
        raw[url_start] ^= 0x01
        container.write_bytes(bytes(raw))
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "stage", self.k_pkg, self.package_id
            )

    def test_wrong_key_or_package_rejected(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(source, container, self.k_pkg, self.package_id)
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "s1", os.urandom(32), self.package_id
            )
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "s2", self.k_pkg, new_hex_id(PKG_ID_BYTES)
            )

    def test_truncation_rejected(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(source, container, self.k_pkg, self.package_id)
        raw = container.read_bytes()
        container.write_bytes(raw[: len(raw) // 2])
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "stage", self.k_pkg, self.package_id
            )

    def test_non_empty_staging_rejected(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(source, container, self.k_pkg, self.package_id)
        staging = self.root / "stage"
        staging.mkdir()
        (staging / "leftover").write_text("x")
        with self.assertRaises(ValidationError):
            unpack_container(container, staging, self.k_pkg, self.package_id)

    def _attempt(self, entries, payloads, *, trailing=b"", name="bad") -> None:
        container = self.root / f"{name}.vspk"
        manifest = _build_manifest(self.package_id, entries)
        _write_container(
            container, self.package_id, self.k_pkg, manifest, payloads, trailing=trailing
        )
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / f"stage-{name}", self.k_pkg, self.package_id
            )

    def test_rejects_traversal_and_windows_special_paths(self) -> None:
        bad_paths = [
            "../evil.txt",
            "a/../../evil.txt",
            "/etc/passwd",
            "C:/Windows/win.ini",
            "\\\\server\\share\\x",
            "dir\\file.txt",
            "file.txt:stream",
            "CON",
            "con.txt",
            "LPT1.log",
            "trailing.",
            "trailing ",
            "a//b",
        ]
        for index, path in enumerate(bad_paths):
            self._attempt(
                [{"path": path, "type": "file", "size": 1, "mime": "text/plain"}],
                [b"x"],
                name=f"bad-{index}",
            )

    def test_rejects_case_insensitive_duplicates(self) -> None:
        self._attempt(
            [
                {"path": "A.txt", "type": "file", "size": 1, "mime": "text/plain"},
                {"path": "a.txt", "type": "file", "size": 1, "mime": "text/plain"},
            ],
            [b"x", b"y"],
            name="dup-case",
        )

    def test_rejects_manifest_size_mismatch(self) -> None:
        self._attempt(
            [{"path": "a.txt", "type": "file", "size": 5, "mime": "text/plain"}],
            [b"abc"],
            name="short",
        )
        self._attempt(
            [{"path": "a.txt", "type": "file", "size": 2, "mime": "text/plain"}],
            [b"abcdef"],
            name="long",
        )

    def test_rejects_trailing_content(self) -> None:
        self._attempt(
            [{"path": "a.txt", "type": "file", "size": 2, "mime": "text/plain"}],
            [b"ab"],
            trailing=b"extra",
            name="trailing",
        )

    def test_rejects_bad_manifest_fields(self) -> None:
        container = self.root / "bad-total.vspk"
        manifest = _build_manifest(
            self.package_id,
            [{"path": "a.txt", "type": "file", "size": 2, "mime": "text/plain"}],
            total_bytes=3,
        )
        _write_container(container, self.package_id, self.k_pkg, manifest, [b"ab"])
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "stage-total", self.k_pkg, self.package_id
            )

        container = self.root / "bad-pkg.vspk"
        manifest = _build_manifest(
            new_hex_id(PKG_ID_BYTES),
            [{"path": "a.txt", "type": "file", "size": 2, "mime": "text/plain"}],
        )
        _write_container(container, self.package_id, self.k_pkg, manifest, [b"ab"])
        with self.assertRaises(ValidationError):
            unpack_container(
                container, self.root / "stage-pkg", self.k_pkg, self.package_id
            )

    def test_symlink_in_source_rejected(self) -> None:
        source = self.root / "src-link"
        source.mkdir()
        target = self.root / "outside.txt"
        target.write_text("secret")
        link = source / "link.txt"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("当前系统不允许创建符号链接")
        with self.assertRaises(ValidationError):
            pack_directory(source, self.root / "x.vspk", self.k_pkg, self.package_id)


if __name__ == "__main__":
    unittest.main()
