"""分享卡片与“从卡片/容器读取提示”的测试。"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import write_source_tree  # noqa: E402

from vaultshare.client.share_card import (  # noqa: E402
    SHARE_CARD_FORMAT,
    build_card,
    load_card,
    write_card,
)
from vaultshare.errors import ValidationError  # noqa: E402
from vaultshare.gui.actions import load_source_hint  # noqa: E402
from vaultshare.protocol.container import pack_directory  # noqa: E402
from vaultshare.util.ids import PKG_ID_BYTES, new_hex_id  # noqa: E402

_FP = "a" * 64
_BFP = "b" * 64


class ShareCardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vaultshare-card-"))
        self.package_id = new_hex_id(PKG_ID_BYTES)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_roundtrip_without_code(self) -> None:
        card = build_card(
            package_id=self.package_id,
            server="http://127.0.0.1:5000/",
            sender_fingerprint=_FP.upper(),
            broker_fingerprint=_BFP,
        )
        path = self.root / "share-card.json"
        write_card(path, card)
        loaded = load_card(path)
        self.assertEqual(loaded.package_id, self.package_id)
        self.assertEqual(loaded.server, "http://127.0.0.1:5000")
        self.assertEqual(loaded.sender_fingerprint, _FP)
        self.assertIsNone(loaded.code)
        self.assertEqual(loaded.record()["format"], SHARE_CARD_FORMAT)

    def test_roundtrip_with_code(self) -> None:
        code = "ABCDE-FGHJK-MNPQR-STVWX-YZ0123"
        card = build_card(
            package_id=self.package_id,
            server="https://example.test",
            sender_fingerprint=_FP,
            broker_fingerprint=_BFP,
            code=code.lower().replace("-", " "),
        )
        path = self.root / "card.json"
        write_card(path, card)
        loaded = load_card(path)
        from vaultshare.util.base32c import format_code

        self.assertEqual(loaded.code, format_code(code))

    def test_invalid_inputs_rejected(self) -> None:
        cases = [
            {"server": "ftp://host", "sender_fingerprint": _FP, "broker_fingerprint": _BFP},
            {"server": "http://host", "sender_fingerprint": "xyz", "broker_fingerprint": _BFP},
            {"server": "http://host", "sender_fingerprint": _FP, "broker_fingerprint": "b" * 63},
            {"server": "http://user:pw@host", "sender_fingerprint": _FP,
             "broker_fingerprint": _BFP},
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValidationError):
                    build_card(package_id=self.package_id, **case)

    def test_wrong_format_rejected(self) -> None:
        path = self.root / "wrong.json"
        path.write_text('{"format":"other","version":1}', encoding="utf-8")
        with self.assertRaises(ValidationError):
            load_card(path)

    def test_source_hint_from_card(self) -> None:
        card = build_card(
            package_id=self.package_id,
            server="http://127.0.0.1:5000",
            sender_fingerprint=_FP,
            broker_fingerprint=_BFP,
        )
        path = self.root / "share-card.json"
        write_card(path, card)
        hint = load_source_hint(str(path))
        self.assertEqual(hint.kind, "card")
        self.assertEqual(hint.server, "http://127.0.0.1:5000")
        self.assertEqual(hint.package_id, self.package_id)
        self.assertEqual(hint.sender_fingerprint, _FP)

    def test_source_hint_from_container(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(
            source,
            container,
            os.urandom(32),
            self.package_id,
            server_url="https://example.test",
        )
        hint = load_source_hint(str(container))
        self.assertEqual(hint.kind, "container")
        self.assertEqual(hint.server, "https://example.test")
        self.assertEqual(hint.package_id, self.package_id)
        self.assertEqual(hint.sender_fingerprint, "")
        self.assertIsNone(hint.code)
        self.assertTrue(hint.require_sender_fingerprint)

    def test_source_hint_reports_optional_fingerprint(self) -> None:
        source = write_source_tree(self.root / "src")
        container = self.root / "payload.vspk"
        pack_directory(
            source,
            container,
            os.urandom(32),
            self.package_id,
            server_url="https://example.test",
            require_sender_fingerprint=False,
        )
        hint = load_source_hint(str(container))
        self.assertFalse(hint.require_sender_fingerprint)


if __name__ == "__main__":
    unittest.main()
