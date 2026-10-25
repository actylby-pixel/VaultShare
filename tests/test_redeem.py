"""兑换状态机：三阶段交付、幂等、额度、撤销、票据绑定与并发。"""

from __future__ import annotations

import multiprocessing
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import Env, FakeBroker, make_sender  # noqa: E402

from vaultshare.broker.service import SoftwareKeyBroker  # noqa: E402
from vaultshare.crypto import hpke  # noqa: E402
from vaultshare.errors import (  # noqa: E402
    Conflict,
    Forbidden,
    Gone,
    Unavailable,
    ValidationError,
    VaultShareError,
)
from vaultshare.protocol.container import unpack_container  # noqa: E402
from vaultshare.protocol.envelope import open_envelope  # noqa: E402
from vaultshare.protocol.redeem import build_redeem_request  # noqa: E402
from vaultshare.server.redeem_flow import redeem  # noqa: E402
from vaultshare.storage.package_store import payload_path  # noqa: E402
from vaultshare.storage.secrets import read_state_mac_key  # noqa: E402
from vaultshare.storage.state import StateStore  # noqa: E402
from vaultshare.util.canonical import canonical_bytes  # noqa: E402
from vaultshare.util.ids import new_hex_id  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402


def _public_failure(exc: VaultShareError) -> tuple[int, str, str]:
    """服务器对外暴露的完整错误标识：状态码、code、message 都必须一致。"""
    return (int(exc.status), str(exc.code), exc.message)


def _request(env: Env, package, code: str, *, request_id=None):
    recipient_private, recipient_public = hpke.generate_keypair()
    outer, _inner = build_redeem_request(
        package_id=package.package_id,
        broker_hpke_public=env.broker_identity.hpke_public,
        code=code,
        recipient_public_key=recipient_public,
        request_id=request_id,
    )
    return outer, recipient_private, recipient_public


def _open(env: Env, package, envelope: dict, outer: dict, recipient_private: bytes) -> bytes:
    core = envelope["envelope_core"]
    k_pkg = open_envelope(
        envelope,
        recipient_private_key=recipient_private,
        broker_signing_public=env.broker_identity.signing_public,
        package_id=package.package_id,
        grant_id=core["grant_id"],
        request_id=outer["request_id"],
        config_version=1,
        broker_key_id=env.keys.key_id,
    )
    return bytes(k_pkg)


def _redeem_worker(settings, package_id, outer, queue) -> None:
    """多进程并发测试的入口（Windows spawn 要求顶层函数）。"""
    try:
        store = StateStore(settings, read_state_mac_key(settings))
        store.startup()  # 启动清理与回放全程持有状态锁
        service = SoftwareKeyBroker(settings)
        context = SimpleNamespace(
            settings=settings,
            store=store,
            broker=FakeBroker(service),
            audit=None,
        )
        redeem(context, outer)
        queue.put("ok")
    except VaultShareError as exc:
        queue.put(exc.code)
    except Exception as exc:  # noqa: BLE001
        queue.put(f"error:{type(exc).__name__}")


class RedeemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env("vaultshare-redeem-")
        self.sender = make_sender()

    def tearDown(self) -> None:
        self.env.close()

    # ------------------------------------------------------------ 主链路
    def test_full_redemption_delivers_working_key(self) -> None:
        package = self.env.create_package(
            self.sender, codes=1, max_uses=2, source=None
        )
        code = package.first_code
        outer, recipient_private, _recipient_public = _request(self.env, package, code)

        outcome = redeem(self.env.context, outer)
        self.assertFalse(outcome.replayed)
        k_pkg = _open(self.env, package, outcome.envelope, outer, recipient_private)

        # 解出来的密钥必须真的能解开服务器上的容器。
        staging = self.env.root / "unpacked"
        manifest = unpack_container(
            payload_path(self.env.settings, package.package_id),
            staging,
            k_pkg,
            package.package_id,
        )
        self.assertEqual(manifest["total_files"], 3)
        self.assertTrue((staging / "hello.txt").is_file())

        grant = self.env.store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 1)
        body = self.env.store.snapshot()["body"]
        self.assertEqual(body["requests"][outer["request_id"]]["status"], "DELIVERED")
        self.assertEqual(body["grants_counters"][package.package_id]["used"], 1)

    def test_replay_returns_byte_identical_envelope_without_charging(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=3)
        outer, _rpriv, _rpub = _request(self.env, package, package.first_code)

        first = redeem(self.env.context, outer)
        second = redeem(self.env.context, outer)
        self.assertTrue(second.replayed)
        self.assertEqual(
            canonical_bytes(first.envelope), canonical_bytes(second.envelope)
        )
        grant = self.env.store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 1)

    def test_same_request_id_with_different_content_rejected(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=3)
        outer, _rpriv, _rpub = _request(self.env, package, package.first_code)
        redeem(self.env.context, outer)

        other, _other_priv, _other_pub = _request(
            self.env,
            package,
            package.first_code,
            request_id=outer["request_id"],
        )
        with self.assertRaises(Conflict):
            redeem(self.env.context, other)

    def test_invalid_code_is_forbidden(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        from vaultshare.util.base32c import generate_code

        outer, _p, _q = _request(self.env, package, generate_code())
        with self.assertRaises(Forbidden) as ctx:
            redeem(self.env.context, outer)
        self.assertEqual(_public_failure(ctx.exception), (403, "invalid_code", "口令无效"))
        self.assertEqual(
            self.env.store.snapshot()["body"]["grants"][package.first_grant_id]["used"],
            0,
        )

    def test_exhausted_grant_is_indistinguishable_from_invalid_code(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        outer, _p, _q = _request(self.env, package, package.first_code)
        redeem(self.env.context, outer)

        second, _p2, _q2 = _request(self.env, package, package.first_code)
        with self.assertRaises(Forbidden) as ctx:
            redeem(self.env.context, second)
        # 与“口令不存在”必须给出完全相同的对外响应，否则可用于枚举有效口令。
        self.assertEqual(_public_failure(ctx.exception), (403, "invalid_code", "口令无效"))
        self.assertEqual(
            self.env.store.snapshot()["body"]["grants"][package.first_grant_id]["used"],
            1,
        )

    def test_revoked_grant_is_indistinguishable_from_invalid_code(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=3)
        grant_id = package.first_grant_id

        def revoke(body: dict) -> None:
            body["grants"][grant_id]["revoked"] = True

        self.env.store.transaction(revoke)
        outer, _p, _q = _request(self.env, package, package.first_code)
        with self.assertRaises(Forbidden) as ctx:
            redeem(self.env.context, outer)
        self.assertEqual(_public_failure(ctx.exception), (403, "invalid_code", "口令无效"))
        self.assertEqual(
            self.env.store.snapshot()["body"]["grants"][grant_id]["used"], 0
        )

    def test_revoked_package_is_rejected(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)

        def revoke(body: dict) -> None:
            body["packages"][package.package_id]["status"] = "revoked"
            body["revoked_packages"][package.package_id] = now()

        self.env.store.transaction(revoke)
        outer, _p, _q = _request(self.env, package, package.first_code)
        with self.assertRaises(ValidationError):
            redeem(self.env.context, outer)

    def test_degraded_state_blocks_redemption(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        outer, _p, _q = _request(self.env, package, package.first_code)
        self.env.store.degraded = True
        self.env.store.degraded_reason = "test"
        with self.assertRaises(Unavailable):
            redeem(self.env.context, outer)

    # ------------------------------------------------------------ 额度
    def test_cumulative_quota_cannot_be_bypassed_by_batches(self) -> None:
        package = self.env.create_package(self.sender, codes=3, max_uses=1)
        with self.assertRaises(ValidationError) as ctx:
            self.env.issue(package, count=1, uses=1, expires_at=now() + 600)
        self.assertEqual(ctx.exception.code, "quota_denied")
        # 已签发 3 个，仍可消费；第 4 个无法签发。
        self.assertEqual(
            len(
                [
                    g
                    for g in self.env.store.snapshot()["body"]["grants"].values()
                    if g["package_id"] == package.package_id
                ]
            ),
            3,
        )

    def test_reservation_recomputes_counters_from_grants(self) -> None:
        # 预留事务不使用缓存计数器，而是从授权记录重新求和；篡改计数器不能
        # 让已耗尽的口令再被消费。
        package = self.env.create_package(self.sender, codes=2, max_uses=1)
        outer1, _p1, _q1 = _request(self.env, package, package.codes[0][1])
        outer2, _p2, _q2 = _request(self.env, package, package.codes[1][1])
        redeem(self.env.context, outer1)
        redeem(self.env.context, outer2)

        def zero_counters(body: dict) -> None:
            body["grants_counters"][package.package_id] = {
                "issued": 0,
                "allocated_uses": 0,
                "used": 0,
            }

        self.env.store.transaction(zero_counters)
        outer3, _p3, _q3 = _request(self.env, package, package.codes[0][1])
        with self.assertRaises(Forbidden) as ctx:
            redeem(self.env.context, outer3)
        self.assertEqual(_public_failure(ctx.exception), (403, "invalid_code", "口令无效"))
        grants = self.env.store.snapshot()["body"]["grants"]
        self.assertEqual(grants[package.codes[0][0]]["used"], 1)
        self.assertEqual(grants[package.codes[1][0]]["used"], 1)

    # ------------------------------------------------------------ 票据/预留
    def test_deliver_rejects_reservation_mismatch(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        outer, _rpriv, _rpub = _request(self.env, package, package.first_code)
        snapshot = self.env.store.snapshot()
        from vaultshare.storage.state import envelope_digest

        ticket = self.env.broker.authorize(
            {
                "outer": outer,
                "state_generation": snapshot["generation"],
                "state_digest": envelope_digest(snapshot),
            }
        )["ticket"]

        reservation_id = new_hex_id(16)

        def reserve(body: dict, generation: int) -> None:
            grant = body["grants"][ticket["grant_id"]]
            grant["used"] = int(grant.get("used", 0)) + 1
            body["requests"][outer["request_id"]] = {
                "package_id": package.package_id,
                "grant_id": ticket["grant_id"],
                "recipient_pk_hash": ticket["recipient_pk_hash"],
                "status": "RESERVED",
                "authorization_id": ticket["authorization_id"],
                "reservation_id": reservation_id,
                "state_generation": generation,
                "reserved_at": now(),
                "delivered_at": 0,
                "opaque_request": __import__(
                    "vaultshare.server.redeem_flow", fromlist=["_outer_digest_b64"]
                )._outer_digest_b64(outer),
                "ticket": ticket,
                "envelope_core": None,
                "receipt": None,
            }

        self.env.store.transaction(reserve, with_generation=True)

        with self.assertRaises(ValidationError) as ctx:
            self.env.broker.deliver(
                {"outer": outer, "ticket": ticket, "reservation_id": new_hex_id(16)}
            )
        self.assertEqual(ctx.exception.code, "reservation_invalid")

        # 正确的 reservation_id 可以通过。
        delivered = self.env.broker.deliver(
            {"outer": outer, "ticket": ticket, "reservation_id": reservation_id}
        )
        _open(self.env, package, delivered["envelope"], outer, _rpriv)

    def test_deliver_rejects_ticket_for_other_grant(self) -> None:
        package = self.env.create_package(self.sender, codes=2, max_uses=1)
        outer, _rpriv, _rpub = _request(self.env, package, package.codes[0][1])
        snapshot = self.env.store.snapshot()
        from vaultshare.storage.state import envelope_digest

        ticket = self.env.broker.authorize(
            {
                "outer": outer,
                "state_generation": snapshot["generation"],
                "state_digest": envelope_digest(snapshot),
            }
        )["ticket"]
        forged = dict(ticket)
        forged["grant_id"] = package.codes[1][0]
        with self.assertRaises(ValidationError):
            self.env.broker.deliver(
                {
                    "outer": outer,
                    "ticket": forged,
                    "reservation_id": new_hex_id(16),
                }
            )

    # ------------------------------------------------------------ 并发
    def test_threads_cannot_overdraw_last_slot(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        requests = [
            _request(self.env, package, package.first_code)[0] for _ in range(8)
        ]
        results: list[str] = []
        lock = threading.Lock()

        def worker(outer):
            try:
                redeem(self.env.context, outer)
                outcome = "ok"
            except Gone:
                outcome = "gone"
            except Unavailable:
                outcome = "unavailable"
            except Exception as exc:  # noqa: BLE001
                outcome = f"error:{type(exc).__name__}"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(outer,)) for outer in requests]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)

        self.assertEqual(results.count("ok"), 1, results)
        self.assertEqual(
            self.env.store.snapshot()["body"]["grants"][package.first_grant_id]["used"],
            1,
        )

    def test_processes_cannot_overdraw_last_slot(self) -> None:
        package = self.env.create_package(self.sender, codes=1, max_uses=1)
        requests = [
            _request(self.env, package, package.first_code)[0] for _ in range(3)
        ]
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        processes = [
            context.Process(
                target=_redeem_worker,
                args=(self.env.settings, package.package_id, outer, queue),
            )
            for outer in requests
        ]
        for process in processes:
            process.start()
        outcomes = []
        try:
            for _ in processes:
                outcomes.append(queue.get(timeout=60))
        finally:
            for process in processes:
                process.join(30)
                if process.is_alive():
                    process.terminate()
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        store = StateStore(self.env.settings, read_state_mac_key(self.env.settings))
        store.startup()
        grant = store.snapshot()["body"]["grants"][package.first_grant_id]
        self.assertEqual(grant["used"], 1)
        self.assertEqual(
            len(
                [
                    r
                    for r in store.snapshot()["body"]["requests"].values()
                    if r.get("grant_id") == package.first_grant_id
                ]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
