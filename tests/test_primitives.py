"""协议不变量：规范化、签名域、HPKE、信封/回执、口令、路径与状态 MAC。"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401  (path setup + fixture helpers)
from support import make_sender, make_settings  # noqa: E402

from vaultshare.crypto import hpke  # noqa: E402
from vaultshare.crypto.keys import (  # noqa: E402
    DOMAIN_POLICY,
    DOMAIN_SENDER_IDENTITY,
    Ed25519Keys,
    broker_fingerprint,
    sign_object,
    verify_object,
)
from vaultshare.errors import CorruptState, ValidationError  # noqa: E402
from vaultshare.protocol.envelope import (  # noqa: E402
    make_envelope,
    make_envelope_core,
    open_envelope,
    verify_envelope_binding,
)
from vaultshare.protocol.grants import (  # noqa: E402
    code_verifier,
    make_grant,
    verify_code,
)
from vaultshare.protocol.identity import (  # noqa: E402
    build_broker_identity,
    check_policy_binding,
    verify_broker_identity,
    verify_sender_identity,
)
from vaultshare.protocol.keyconfig import build_keyconfig, verify_keyconfig  # noqa: E402
from vaultshare.protocol.policy import (  # noqa: E402
    build_policy,
    check_new_grants,
    check_redemption,
    grant_metrics,
    policy_digest,
    verify_policy,
)
from vaultshare.protocol.receipt import envelope_sha256, verify_receipt  # noqa: E402
from vaultshare.protocol.redeem import build_redeem_request, open_redeem_request  # noqa: E402
from vaultshare.storage.secrets import read_state_mac_key  # noqa: E402
from vaultshare.storage.state import (  # noqa: E402
    empty_body,
    seal_envelope,
    verify_envelope,
)
from vaultshare.storage.state import StateStore  # noqa: E402
from vaultshare.util.base32c import (  # noqa: E402
    ALPHABET,
    CODE_CHARS,
    format_code,
    generate_code,
    is_valid_code,
    normalize_code,
)
from vaultshare.util.canonical import (  # noqa: E402
    b64u_decode,
    b64u_encode,
    canonical_bytes,
    fixed_domain,
)
from vaultshare.util.ids import PKG_ID_BYTES, new_hex_id  # noqa: E402
from vaultshare.util.pathcheck import PathRejected, ensure_within, validate_relpath  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402


class CanonicalTests(unittest.TestCase):
    def test_canonical_json_is_stable(self) -> None:
        first = canonical_bytes({"b": 1, "a": "中文", "c": [3, 2, 1]})
        second = canonical_bytes({"c": [3, 2, 1], "a": "中文", "b": 1})
        self.assertEqual(first, second)
        self.assertIn("中文".encode("utf-8"), first)
        self.assertNotIn(b" ", first)

    def test_b64url_has_no_padding_and_roundtrips(self) -> None:
        raw = bytes(range(40))
        encoded = b64u_encode(raw)
        self.assertNotIn("=", encoded)
        self.assertEqual(b64u_decode(encoded), raw)
        with self.assertRaises(ValueError):
            b64u_decode(encoded, expected_len=41)

    def test_fixed_domain_is_length_prefixed(self) -> None:
        encoded = fixed_domain(b"a", b"b", b"cc")
        self.assertEqual(
            encoded,
            b"\x00\x00\x00\x01a" + b"\x00\x00\x00\x01b" + b"\x00\x00\x00\x02cc",
        )
        # 长度前缀消除了 "ab"+"c" 与 "a"+"bc" 的歧义。
        self.assertNotEqual(
            fixed_domain(b"a", b"bc"), fixed_domain(b"ab", b"c")
        )


class SignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = Ed25519Keys.generate()

    def test_signature_is_domain_separated(self) -> None:
        obj = {"a": 1, "b": "x"}
        signed = sign_object(self.keys, DOMAIN_POLICY, obj)
        self.assertIsInstance(signed["signature"], str)
        json.dumps(signed)  # 必须可序列化
        self.assertTrue(verify_object(self.keys.public_bytes, DOMAIN_POLICY, signed))
        self.assertFalse(
            verify_object(self.keys.public_bytes, DOMAIN_SENDER_IDENTITY, signed)
        )

    def test_any_field_change_invalidates_signature(self) -> None:
        signed = sign_object(self.keys, DOMAIN_POLICY, {"a": 1})
        signed["a"] = 2
        self.assertFalse(verify_object(self.keys.public_bytes, DOMAIN_POLICY, signed))

    def test_bad_signature_shapes_are_rejected(self) -> None:
        signed = sign_object(self.keys, DOMAIN_POLICY, {"a": 1})
        for bad in (None, 123, "not-base64!", b"short"):
            candidate = dict(signed)
            candidate["signature"] = bad
            self.assertFalse(
                verify_object(self.keys.public_bytes, DOMAIN_POLICY, candidate)
            )


class HpkeTests(unittest.TestCase):
    def test_roundtrip_and_wire_format(self) -> None:
        private, public = hpke.generate_keypair()
        wrapped = hpke.seal(public, b"secret", b"info-v1")
        self.assertEqual(len(wrapped), 32 + len(b"secret") + 16)
        enc, ct = hpke.split_wrap(wrapped)
        self.assertEqual(len(enc), 32)
        self.assertEqual(hpke.join_wrap(enc, ct), wrapped)
        self.assertEqual(hpke.open_sealed(private, wrapped, b"info-v1"), b"secret")

    def test_wrong_info_or_tamper_fails(self) -> None:
        private, public = hpke.generate_keypair()
        wrapped = hpke.seal(public, b"secret", b"info-v1")
        with self.assertRaises(hpke.DecryptionFailed):
            hpke.open_sealed(private, wrapped, b"info-v2")
        tampered = bytearray(wrapped)
        tampered[-1] ^= 1
        with self.assertRaises(hpke.DecryptionFailed):
            hpke.open_sealed(private, bytes(tampered), b"info-v1")
        other_private, _ = hpke.generate_keypair()
        with self.assertRaises(hpke.DecryptionFailed):
            hpke.open_sealed(other_private, wrapped, b"info-v1")

    def test_short_ciphertext_rejected(self) -> None:
        private, _ = hpke.generate_keypair()
        with self.assertRaises(hpke.DecryptionFailed):
            hpke.open_sealed(private, b"\x00" * 40, b"info")


class Base32Tests(unittest.TestCase):
    def test_generated_codes_are_valid_and_unique(self) -> None:
        codes = {generate_code() for _ in range(50)}
        self.assertEqual(len(codes), 50)
        for code in codes:
            self.assertEqual(len(code), CODE_CHARS)
            self.assertTrue(is_valid_code(code))
            self.assertTrue(set(code) <= set(ALPHABET))

    def test_normalization_and_formatting(self) -> None:
        code = generate_code()
        noisy = "-".join(
            [code[:5], code[5:10], code[10:15], code[15:20], code[20:]]
        ).lower()
        noisy = noisy.replace("0", "o").replace("1", "l")
        self.assertEqual(normalize_code(noisy), code)
        self.assertEqual(format_code(code).replace("-", ""), code)
        self.assertEqual(
            format_code(code), "-".join(code[i : i + 5] for i in range(0, 26, 5))
        )

    def test_invalid_codes_rejected(self) -> None:
        for bad in ("", "ABC", "A" * 25, "A" * 27, "A" * 12 + "!" + "A" * 13, "U" * 26):
            self.assertFalse(is_valid_code(bad), bad)
        with self.assertRaises(ValueError):
            normalize_code("abc\u0000def")

    def test_verifier_binding_and_constant_time_compare(self) -> None:
        key = os.urandom(32)
        code = generate_code()
        grant = make_grant(
            grant_id=new_hex_id(16),
            package_id=new_hex_id(PKG_ID_BYTES),
            code_verifier_hex=code_verifier(code, key),
            sealed_code={"enc": b64u_encode(b"e" * 32), "ciphertext": b64u_encode(b"c" * 10)},
            expires_at=now() + 60,
            max_uses=1,
            policy_version=1,
            batch_id=new_hex_id(16),
            created_at=now(),
        )
        self.assertTrue(verify_code(code, grant["code_verifier"], key))
        self.assertFalse(verify_code(generate_code(), grant["code_verifier"], key))


class PathTests(unittest.TestCase):
    def test_rejects_dangerous_paths(self) -> None:
        bad = [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "C:/Windows/win.ini",
            "C:evil",
            "\\\\server\\share\\x",
            "a\\b",
            "dir/a.txt:stream",
            "CON",
            "con.txt",
            "LPT1.log",
            "trailing.",
            "trailing ",
            "nul\x00byte",
            "a//b",
            "",
        ]
        for value in bad:
            with self.assertRaises(PathRejected, msg=value):
                validate_relpath(value)

    def test_accepts_normal_paths(self) -> None:
        for value in ("a.txt", "dir/sub/file.bin", "中文/文件.txt", ".hidden"):
            self.assertEqual(str(validate_relpath(value)), value)

    def test_ensure_within(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            inner = os.path.join(root, "a", "b")
            os.makedirs(inner)
            self.assertTrue(ensure_within(root, inner, allow_root=True))
            self.assertTrue(ensure_within(root, inner))
            with self.assertRaises(PathRejected):
                ensure_within(root, root)
            with self.assertRaises(PathRejected):
                ensure_within(root, os.path.join(root, "..", "outside"))


class IdentityAndKeyConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sender = make_sender()
        self.broker_keys = hpke.generate_keypair()
        self.signing = Ed25519Keys.generate()
        self.broker = build_broker_identity(
            new_hex_id(16),
            self.broker_keys[1],
            self.signing.public_bytes,
            created_at=now(),
        )

    def test_sender_identity_binds_both_keys(self) -> None:
        identity = verify_sender_identity(self.sender.identity.record)
        self.assertEqual(identity.digest, self.sender.identity.digest)
        tampered = dict(self.sender.identity.record)
        tampered["x25519_public_key"] = b64u_encode(os.urandom(32))
        with self.assertRaises(ValidationError):
            verify_sender_identity(tampered)

    def test_broker_fingerprint_must_match_keys(self) -> None:
        record = dict(self.broker.record)
        self.assertEqual(verify_broker_identity(record).fingerprint, self.broker.fingerprint)
        record["hpke_public_key"] = b64u_encode(os.urandom(32))
        with self.assertRaises(ValidationError):
            verify_broker_identity(record)
        with self.assertRaises(ValidationError):
            verify_broker_identity(self.broker.record, expected_fingerprint="0" * 64)

    def test_keyconfig_requires_sender_binding_and_signature(self) -> None:
        package_id = new_hex_id(PKG_ID_BYTES)
        policy = build_policy(
            package_id,
            self.sender.identity,
            self.sender.ed25519_private,
            max_codes=1,
            max_uses_per_code=1,
            max_total_redemptions=1,
            latest_expiry=now() + 600,
            created_at=now(),
        )
        kc = build_keyconfig(
            package_id,
            policy_digest(policy),
            b"k" * 32,
            self.broker,
            self.sender.identity,
            self.sender.ed25519_private,
            created_at=now(),
        )
        parsed = verify_keyconfig(kc, self.sender.identity)
        self.assertEqual(parsed.package_id, package_id)
        self.assertEqual(parsed.broker_fingerprint, self.broker.fingerprint)

        # 换成另一份身份（不同 X25519/Ed25519）必须失败。
        other = make_sender()
        with self.assertRaises(ValidationError):
            verify_keyconfig(kc, other.identity)
        # 篡改发送方公钥后签名失效。
        tampered = dict(kc)
        tampered["sender_public_key"] = b64u_encode(other.identity.ed25519_public)
        with self.assertRaises(ValidationError):
            verify_keyconfig(tampered)

    def test_policy_binding_helpers(self) -> None:
        package_id = new_hex_id(PKG_ID_BYTES)
        policy = build_policy(
            package_id,
            self.sender.identity,
            self.sender.ed25519_private,
            max_codes=2,
            max_uses_per_code=3,
            max_total_redemptions=6,
            latest_expiry=now() + 600,
            created_at=now(),
        )
        check_policy_binding(policy, self.sender.identity)
        other = make_sender()
        with self.assertRaises(ValidationError):
            check_policy_binding(policy, other.identity)


class EnvelopeAndReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker_signing = Ed25519Keys.generate()
        self.recipient_private, self.recipient_public = hpke.generate_keypair()
        self.package_id = new_hex_id(PKG_ID_BYTES)
        self.grant_id = new_hex_id(16)
        self.request_id = new_hex_id(32)
        self.k_pkg = b"K" * 32
        self.core = make_envelope_core(
            k_pkg=self.k_pkg,
            package_id=self.package_id,
            grant_id=self.grant_id,
            request_id=self.request_id,
            recipient_public_key=self.recipient_public,
            config_version=1,
            broker_key_id=new_hex_id(16),
        )
        self.envelope = make_envelope(
            core=self.core,
            broker_signing_private=self.broker_signing.private_bytes,
            issued_at=now(),
        ).to_dict()

    def test_envelope_opens_and_binds_all_fields(self) -> None:
        k_pkg = open_envelope(
            self.envelope,
            recipient_private_key=self.recipient_private,
            broker_signing_public=self.broker_signing.public_bytes,
            package_id=self.package_id,
            grant_id=self.grant_id,
            request_id=self.request_id,
            config_version=1,
            broker_key_id=self.core["key_id"],
        )
        self.assertEqual(bytes(k_pkg), self.k_pkg)
        for field, bad in (
            ("package_id", new_hex_id(PKG_ID_BYTES)),
            ("grant_id", new_hex_id(16)),
            ("request_id", new_hex_id(32)),
            ("config_version", 2),
            ("broker_key_id", new_hex_id(16)),
        ):
            with self.assertRaises(ValidationError, msg=field):
                kwargs = {
                    "package_id": self.package_id,
                    "grant_id": self.grant_id,
                    "request_id": self.request_id,
                    "config_version": 1,
                    "broker_key_id": self.core["key_id"],
                }
                kwargs[field] = bad
                open_envelope(
                    self.envelope,
                    recipient_private_key=self.recipient_private,
                    broker_signing_public=self.broker_signing.public_bytes,
                    **kwargs,
                )

    def test_receipt_hash_covers_only_envelope_core(self) -> None:
        self.assertEqual(
            self.envelope["receipt"]["envelope_sha256"], envelope_sha256(self.core)
        )
        modified = json.loads(json.dumps(self.envelope))
        modified["receipt"]["issued_at"] += 1000
        self.assertEqual(
            modified["receipt"]["envelope_sha256"], envelope_sha256(modified["envelope_core"])
        )
        # 修改 receipt 后签名失效，但哈希仍只由 core 决定。
        with self.assertRaises(ValidationError):
            verify_receipt(
                modified["envelope_core"],
                modified["receipt"],
                self.broker_signing.public_bytes,
            )

    def test_receipt_wrong_key_or_core_mismatch_rejected(self) -> None:
        other = Ed25519Keys.generate()
        with self.assertRaises(ValidationError):
            verify_receipt(
                self.core, self.envelope["receipt"], other.public_bytes
            )
        changed_core = dict(self.core)
        changed_core["config_version"] = 2
        with self.assertRaises(ValidationError):
            verify_receipt(
                changed_core, self.envelope["receipt"], self.broker_signing.public_bytes
            )

    def test_verify_binding_rejects_wrong_recipient(self) -> None:
        with self.assertRaises(ValidationError):
            verify_envelope_binding(
                self.core,
                package_id=self.package_id,
                grant_id=self.grant_id,
                request_id=self.request_id,
                recipient_public_key=os.urandom(32),
                recipient_pk_hash=None,
                config_version=1,
            )


class RedeemRequestTests(unittest.TestCase):
    def test_request_roundtrip_and_tamper(self) -> None:
        private, public = hpke.generate_keypair()
        package_id = new_hex_id(PKG_ID_BYTES)
        recipient_private, recipient_public = hpke.generate_keypair()
        outer, inner = build_redeem_request(
            package_id=package_id,
            broker_hpke_public=public,
            code=generate_code(),
            recipient_public_key=recipient_public,
        )
        opened = open_redeem_request(outer, private)
        self.assertEqual(opened.request_id, outer["request_id"])
        self.assertEqual(opened.code, inner["code"])
        self.assertEqual(opened.recipient_public_key, recipient_public)

        tampered = dict(outer)
        tampered["package_id"] = new_hex_id(PKG_ID_BYTES)
        with self.assertRaises(ValidationError):
            open_redeem_request(tampered, private)

    def test_request_rejects_non_normalized_code_and_skew(self) -> None:
        private, public = hpke.generate_keypair()
        package_id = new_hex_id(PKG_ID_BYTES)
        _rpriv, rpub = hpke.generate_keypair()
        outer, _inner = build_redeem_request(
            package_id=package_id,
            broker_hpke_public=public,
            code=generate_code(),
            recipient_public_key=rpub,
        )
        with self.assertRaises(ValidationError):
            open_redeem_request(outer, private, current_time=now() + 3600)
        import json as _json

        from vaultshare.crypto import hpke as _hpke
        from vaultshare.protocol.signing import redeem_info
        from vaultshare.util.canonical import canonical_bytes as _canon

        inner = {
            "format": "vaultshare-redeem",
            "version": 1,
            "request_id": outer["request_id"],
            "package_id": package_id,
            "recipient_public_key": b64u_encode(rpub),
            "code": generate_code().lower(),
            "created_at": now(),
            "nonce": b64u_encode(os.urandom(16)),
        }
        wrapped = _hpke.seal(public, _canon(inner), redeem_info(bytes.fromhex(package_id)))
        enc, ct = _hpke.split_wrap(wrapped)
        bad_outer = {
            "request_id": outer["request_id"],
            "package_id": package_id,
            "hpke_enc": b64u_encode(enc),
            "ciphertext": b64u_encode(ct),
        }
        with self.assertRaises(ValidationError):
            open_redeem_request(bad_outer, private)
        _ = _json  # keep import explicit for readers


class QuotaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sender = make_sender()
        self.package_id = new_hex_id(PKG_ID_BYTES)
        self.policy = verify_policy(
            build_policy(
                self.package_id,
                self.sender.identity,
                self.sender.ed25519_private,
                max_codes=3,
                max_uses_per_code=2,
                max_total_redemptions=5,
                latest_expiry=now() + 3600,
                created_at=now(),
            )
        )

    def _grant(self, *, used=0, max_uses=2, revoked=False):
        return {
            "package_id": self.package_id,
            "max_uses": max_uses,
            "used": used,
            "revoked": revoked,
            "expires_at": now() + 600,
        }

    def test_cumulative_code_limit_across_batches(self) -> None:
        grants = {"g1": self._grant(), "g2": self._grant()}
        check_new_grants(
            self.policy, grants, count=1, uses_per_code=1, expires_at=now() + 600
        )
        with self.assertRaises(ValidationError) as ctx:
            check_new_grants(
                self.policy, grants, count=2, uses_per_code=1, expires_at=now() + 600
            )
        self.assertEqual(ctx.exception.code, "quota_denied")

    def test_cumulative_allocated_uses_limit(self) -> None:
        # max_total_redemptions=5，已有 2 个口令各 2 次 = 4，再申请 1×2 超限。
        grants = {"g1": self._grant(), "g2": self._grant()}
        with self.assertRaises(ValidationError) as ctx:
            check_new_grants(
                self.policy, grants, count=1, uses_per_code=2, expires_at=now() + 600
            )
        self.assertEqual(ctx.exception.code, "quota_denied")
        check_new_grants(
            self.policy, grants, count=1, uses_per_code=1, expires_at=now() + 600
        )

    def test_expiry_and_per_code_limits(self) -> None:
        with self.assertRaises(ValidationError):
            check_new_grants(
                self.policy,
                {},
                count=1,
                uses_per_code=3,
                expires_at=now() + 60,
            )
        with self.assertRaises(ValidationError):
            check_new_grants(
                self.policy,
                {},
                count=1,
                uses_per_code=1,
                expires_at=self.policy.latest_expiry + 1,
            )

    def test_redemption_checks(self) -> None:
        check_redemption(self.policy, self._grant(), now=now())
        for grant, code in (
            (self._grant(revoked=True), "grant_revoked"),
            (self._grant(used=2), "grant_exhausted"),
            ({**self._grant(), "expires_at": now() - 1}, "grant_expired"),
        ):
            with self.assertRaises(ValidationError) as ctx:
                check_redemption(self.policy, grant, now=now())
            self.assertEqual(ctx.exception.code, code)

    def test_metrics_include_revoked_grants(self) -> None:
        metrics = grant_metrics(
            {"a": self._grant(revoked=True), "b": self._grant(used=1)}, self.package_id
        )
        self.assertEqual(
            metrics, {"issued": 2, "allocated_uses": 4, "used": 1}
        )


class StateMacTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.root = make_settings()
        self.mac_key = read_state_mac_key(self.settings)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def test_mac_covers_full_envelope(self) -> None:
        env = seal_envelope(self.mac_key, empty_body(), 7)
        verify_envelope(self.mac_key, env)
        for field, value in (
            ("format", "other-format"),
            ("version", 2),
            ("generation", 8),
            ("body", {**empty_body(), "senders": {"x": 1}}),
        ):
            tampered = json.loads(json.dumps(env))
            tampered[field] = value
            with self.assertRaises(CorruptState, msg=field):
                verify_envelope(self.mac_key, tampered)

    def test_wrong_key_rejected(self) -> None:
        env = seal_envelope(self.mac_key, empty_body(), 1)
        with self.assertRaises(CorruptState):
            verify_envelope(os.urandom(32), env)

    def test_real_store_commits_are_verifiable(self) -> None:
        store = StateStore(self.settings, self.mac_key)
        store.startup()

        def mutate(body: dict) -> None:
            body["broker"]["current_key_id"] = "ab" * 16

        store.transaction(mutate)
        raw = self.settings.state_path.read_bytes()
        from vaultshare.storage.state import parse_envelope_bytes

        env = parse_envelope_bytes(self.mac_key, raw)
        self.assertEqual(env["generation"], 1)
        self.assertEqual(env["body"]["broker"]["current_key_id"], "ab" * 16)


if __name__ == "__main__":
    unittest.main()
