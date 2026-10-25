"""接收方指纹核对：可选，但一旦给出就必须匹配；其余验证始终保留。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import Env, make_sender  # noqa: E402

from vaultshare.client.redeem import _verify_public  # noqa: E402
from vaultshare.errors import ValidationError  # noqa: E402


class RedeemFingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env("vaultshare-redeem-fp-")
        self.sender = make_sender()
        self.package = self.env.create_package(self.sender)
        self.materials = {
            "keyconfig": self.package.keyconfig,
            "policy": self.package.policy,
            "sender_identity": self.sender.identity.record,
            "broker_identity": self.env.broker_identity.record,
            "status": "active",
            "payload_sha256": "0" * 64,
        }

    def tearDown(self) -> None:
        self.env.close()

    def test_fingerprint_can_be_omitted(self) -> None:
        kc, policy, broker, digest = _verify_public(
            self.materials, self.package.package_id, None, None
        )
        self.assertEqual(kc.package_id, self.package.package_id)
        self.assertEqual(policy.package_id, self.package.package_id)
        self.assertEqual(broker.key_id, self.env.keys.key_id)
        self.assertEqual(digest, self.sender.identity.digest)

    def test_given_fingerprint_must_match(self) -> None:
        _verify_public(
            self.materials, self.package.package_id, self.sender.identity.digest, None
        )
        with self.assertRaises(ValidationError):
            _verify_public(
                self.materials, self.package.package_id, "0" * 64, None
            )

    def test_other_checks_still_run_without_fingerprint(self) -> None:
        # 身份记录自签名/KeyConfig 绑定被破坏时，即使不核对指纹也必须拒绝。
        broken = dict(self.materials)
        broken["policy"] = dict(self.package.policy)
        broken["policy"]["max_codes"] = 999
        with self.assertRaises(ValidationError):
            _verify_public(broken, self.package.package_id, None, None)

    def test_wrong_broker_fingerprint_still_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            _verify_public(
                self.materials, self.package.package_id, None, "f" * 64
            )


if __name__ == "__main__":
    unittest.main()
