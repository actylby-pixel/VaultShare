"""本地 IPC：HMAC、时间戳、重放、请求 ID 复用与幂等缓存。"""

from __future__ import annotations

import os
import socket
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_settings  # noqa: E402

from vaultshare.broker import ipc  # noqa: E402
from vaultshare.broker.envelope_cache import EnvelopeCache  # noqa: E402
from vaultshare.broker.idempotency import IdempotencyStore  # noqa: E402
from vaultshare.broker.service import TICKET_FORMAT, verify_ticket  # noqa: E402
from vaultshare.crypto.keys import (  # noqa: E402
    DOMAIN_AUTHORIZATION,
    Ed25519Keys,
    sign_object,
)
from vaultshare.errors import IpcError, ValidationError  # noqa: E402
from vaultshare.util.canonical import b64u_encode, canonical_bytes, sha256_hex  # noqa: E402
from vaultshare.util.ids import new_hex_id  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402
from vaultshare.version import PROTOCOL_VERSION  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_message(key: bytes, op: str, body: dict, *, request_id=None, ts=None, seq=1) -> dict:
    message = {
        "v": 1,
        "seq": seq,
        "ts": int(time.time()) if ts is None else int(ts),
        "request_id": request_id or new_hex_id(32),
        "body_sha256": sha256_hex(canonical_bytes(body)),
        "op": op,
        "body": body,
    }
    message["mac"] = ipc._request_mac(key, message).hex()
    return message


def send_raw(port: int, message: dict) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        ipc._frame(sock, message)
        response = ipc._recv_frame(sock)
    assert isinstance(response, dict)
    return response


class IpcTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = os.urandom(32)
        self.calls: list[tuple[str, dict]] = []

        def dispatch(op: str, body: dict, request_id: str, body_sha256: str) -> dict:
            self.calls.append((op, body))
            if body.get("boom"):
                raise RuntimeError("secret internal detail")
            return {"echo": body, "op": op}

        self.port = free_port()
        self.server = ipc.IpcServer("127.0.0.1", self.port, self.key, dispatch)
        self.server.start_background()
        self.client = ipc.IpcClient("127.0.0.1", self.port, self.key, timeout=5)

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_client_roundtrip(self) -> None:
        response = self.client.call("health", {"a": 1})
        self.assertEqual(response, {"echo": {"a": 1}, "op": "health"})

    def test_bind_non_loopback_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ipc.IpcServer("0.0.0.0", self.port, self.key, lambda *a: {})

    def test_bad_hmac(self) -> None:
        message = make_message(self.key, "health", {})
        message["mac"] = "00" * 32
        response = send_raw(self.port, message)
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "bad_mac")
        self.assertEqual(self.calls, [])

    def test_stale_timestamp(self) -> None:
        message = make_message(self.key, "health", {}, ts=now() - ipc.MAX_SKEW - 5)
        response = send_raw(self.port, message)
        self.assertEqual(response["code"], "stale")
        self.assertEqual(self.calls, [])

    def test_body_digest_mismatch(self) -> None:
        message = make_message(self.key, "health", {"a": 1})
        message["body_sha256"] = "0" * 64
        message["mac"] = ipc._request_mac(self.key, message).hex()
        response = send_raw(self.port, message)
        self.assertEqual(response["code"], "bad_digest")
        self.assertEqual(self.calls, [])

    def test_exact_replay_runs_once(self) -> None:
        message = make_message(self.key, "health", {"a": 1})
        first = send_raw(self.port, message)
        second = send_raw(self.port, message)
        self.assertTrue(first["ok"] and second["ok"])
        self.assertEqual(first["body"], second["body"])
        self.assertEqual(len(self.calls), 1)

    def test_request_id_reuse_with_different_body_rejected(self) -> None:
        rid = new_hex_id(32)
        first = make_message(self.key, "health", {"a": 1}, request_id=rid)
        second = make_message(self.key, "health", {"a": 2}, request_id=rid, seq=2)
        self.assertTrue(send_raw(self.port, first)["ok"])
        response = send_raw(self.port, second)
        self.assertEqual(response["code"], "request_id_reuse")
        self.assertEqual(len(self.calls), 1)

    def test_wrong_key_client_cannot_verify(self) -> None:
        client = ipc.IpcClient("127.0.0.1", self.port, os.urandom(32), timeout=5)
        with self.assertRaises(IpcError):
            client.call("health", {})

    def test_internal_error_is_not_leaked(self) -> None:
        response = send_raw(self.port, make_message(self.key, "health", {"boom": True}))
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "internal")
        self.assertNotIn("secret internal detail", response["message"])
        self.assertNotIn("Traceback", response["message"])

    def test_server_response_is_authenticated(self) -> None:
        message = make_message(self.key, "health", {})
        response = send_raw(self.port, message)
        mac = bytes.fromhex(response["mac"])
        self.assertTrue(
            __import__("hmac").compare_digest(mac, ipc._response_mac(self.key, response))
        )


class IdempotencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.root = make_settings("vaultshare-idem-")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def test_persists_across_instances(self) -> None:
        store = IdempotencyStore(self.settings)
        store.put("grants:abc", {"result": 1}, ttl=3600)
        reopened = IdempotencyStore(self.settings)
        self.assertEqual(reopened.get("grants:abc"), {"result": 1})

    def test_expired_entries_are_dropped(self) -> None:
        store = IdempotencyStore(self.settings)
        store.put("k", {"v": 1}, ttl=0)
        self.assertIsNone(store.get("k"))
        self.assertIsNone(IdempotencyStore(self.settings).get("k"))

    def test_corrupt_file_refuses_to_start(self) -> None:
        self.settings.idempotency_path.write_text("not json", encoding="utf-8")
        with self.assertRaises(Exception):
            IdempotencyStore(self.settings)


class EnvelopeCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.root = make_settings("vaultshare-cache-")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def test_roundtrip_and_digest_binding(self) -> None:
        cache = EnvelopeCache(self.settings)
        rid = new_hex_id(32)
        envelope = {"envelope_core": {"a": 1}, "receipt": {"b": 2}}
        self.assertIsNone(cache.get(rid, "d1"))
        cache.put(rid, "d1", envelope)
        self.assertEqual(cache.get(rid, "d1"), envelope)
        with self.assertRaises(ValidationError):
            cache.get(rid, "d2")

    def test_corrupt_entry_is_cache_miss(self) -> None:
        cache = EnvelopeCache(self.settings)
        rid = new_hex_id(32)
        (self.settings.envelopes_dir / f"{rid}.json").write_text("{oops", encoding="utf-8")
        self.assertIsNone(cache.get(rid, "d1"))


class TicketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signing = Ed25519Keys.generate()

    def _ticket(self, **overrides) -> dict:
        ticket = {
            "format": TICKET_FORMAT,
            "version": PROTOCOL_VERSION,
            "authorization_id": new_hex_id(16),
            "grant_id": new_hex_id(16),
            "request_id": new_hex_id(32),
            "recipient_pk_hash": sha256_hex(os.urandom(32)),
            "package_id": new_hex_id(16),
            "policy_hash": sha256_hex(os.urandom(32)),
            "state_generation": 3,
            "state_digest": sha256_hex(os.urandom(32)),
            "issued_at": now(),
            "expires_at": now() + 120,
            "broker_key_id": new_hex_id(16),
        }
        ticket.update(overrides)
        return sign_object(self.signing, DOMAIN_AUTHORIZATION, ticket)

    def test_valid_ticket(self) -> None:
        ticket = self._ticket()
        self.assertEqual(
            verify_ticket(ticket, self.signing.public_bytes)["state_generation"], 3
        )

    def test_expired_and_future_tickets(self) -> None:
        expired = self._ticket(issued_at=now() - 300, expires_at=now() - 10)
        with self.assertRaises(ValidationError):
            verify_ticket(expired, self.signing.public_bytes)
        future = self._ticket(issued_at=now() + 3600, expires_at=now() + 3660)
        with self.assertRaises(ValidationError):
            verify_ticket(future, self.signing.public_bytes)

    def test_tampered_or_foreign_signature(self) -> None:
        ticket = self._ticket()
        ticket["state_generation"] = 4
        with self.assertRaises(ValidationError):
            verify_ticket(ticket, self.signing.public_bytes)
        other = Ed25519Keys.generate()
        with self.assertRaises(ValidationError):
            verify_ticket(self._ticket(), other.public_bytes)

    def test_extra_or_missing_fields_rejected(self) -> None:
        ticket = self._ticket()
        ticket["extra"] = True
        with self.assertRaises(ValidationError):
            verify_ticket(ticket, self.signing.public_bytes)
        ticket = self._ticket()
        ticket.pop("policy_hash")
        with self.assertRaises(ValidationError):
            verify_ticket(ticket, self.signing.public_bytes)


if __name__ == "__main__":
    unittest.main()
