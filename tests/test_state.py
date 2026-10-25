"""状态文件：MAC、journal 回放、压实、损坏降级、备份恢复与写失败注入。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401
from support import make_settings  # noqa: E402

from vaultshare.errors import CorruptState  # noqa: E402
from vaultshare.storage import state as state_module  # noqa: E402
from vaultshare.storage.locking import FileLock, LockTimeout  # noqa: E402
from vaultshare.storage.secrets import read_state_mac_key  # noqa: E402
from vaultshare.storage.state import (  # noqa: E402
    StateStore,
    parse_envelope_bytes,
    seal_envelope,
)


class StateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.settings, self.root = make_settings("vaultshare-state-")
        self.mac_key = read_state_mac_key(self.settings)
        self.store = StateStore(self.settings, self.mac_key)
        self.store.startup()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def _bump(self, store: StateStore | None = None, tag: str = "x") -> None:
        def mutate(body: dict) -> None:
            body["senders"][tag] = {"marker": True}

        (store or self.store).transaction(mutate)

    def _envelope(self) -> dict:
        return parse_envelope_bytes(
            self.mac_key, self.settings.state_path.read_bytes()
        )

    def _write_envelope(self, env: dict) -> None:
        self.settings.state_path.write_bytes(
            json.dumps(env, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )

    # ------------------------------------------------------------ 基本
    def test_startup_creates_generation_zero_and_checkpoint(self) -> None:
        env = self._envelope()
        self.assertEqual(env["generation"], 0)
        self.assertTrue(self.settings.checkpoint_path.exists())

    def test_transaction_generation_journal_and_reload(self) -> None:
        self._bump(tag="a")
        env = self._envelope()
        self.assertEqual(env["generation"], 1)
        self.assertIn("a", env["body"]["senders"])
        journal = self.settings.journal_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(journal), 1)
        journal_env = json.loads(journal[0])
        self.assertEqual(journal_env["generation"], 1)

        reopened = StateStore(self.settings, self.mac_key)
        reopened.startup()
        self.assertEqual(reopened.snapshot()["generation"], 1)
        self.assertIn("a", reopened.snapshot()["body"]["senders"])

    def test_failed_mutator_has_no_side_effects(self) -> None:
        before = self.settings.state_path.read_bytes()

        def mutate(body: dict) -> None:
            body["senders"]["ghost"] = {}
            raise RuntimeError("abort")

        with self.assertRaises(RuntimeError):
            self.store.transaction(mutate)
        self.assertEqual(self.settings.state_path.read_bytes(), before)
        self.assertEqual(self._envelope()["generation"], 0)

    # ------------------------------------------------------------ journal
    def test_journal_replay_after_crash_before_replace(self) -> None:
        old_state = self.settings.state_path.read_bytes()
        self._bump(tag="replayed")
        # 模拟：journal 已 fsync，state 替换尚未发生。
        self.settings.state_path.write_bytes(old_state)
        self.assertEqual(self._envelope()["generation"], 0)

        recovered = StateStore(self.settings, self.mac_key)
        recovered.startup()
        self.assertEqual(recovered.snapshot()["generation"], 1)
        self.assertIn("replayed", recovered.snapshot()["body"]["senders"])
        self.assertEqual(self._envelope()["generation"], 1)

    def test_journal_gap_enters_degraded(self) -> None:
        self._bump(tag="a")
        env = self._envelope()
        # 人为写入不连续的 generation。
        gap = seal_envelope(self.mac_key, env["body"], env["generation"] + 2)
        with open(self.settings.journal_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(gap, ensure_ascii=False) + "\n")
        reopened = StateStore(self.settings, self.mac_key)
        reopened.startup()
        self.assertTrue(reopened.degraded)
        with self.assertRaises(CorruptState):
            reopened.transaction(lambda body: None)

    def test_partial_last_journal_line_is_ignored(self) -> None:
        self._bump()
        with open(self.settings.journal_path, "ab") as f:
            f.write(b'{"format":"vaultshare-state","vers')
        reopened = StateStore(self.settings, self.mac_key)
        reopened.startup()
        self.assertFalse(reopened.degraded)

    def test_journal_compaction(self) -> None:
        old_entries = state_module.JOURNAL_MAX_ENTRIES
        old_bytes = state_module.JOURNAL_MAX_BYTES
        state_module.JOURNAL_MAX_ENTRIES = 3
        state_module.JOURNAL_MAX_BYTES = 10**9
        try:
            for index in range(12):
                self._bump(tag=f"k{index}")
            journal = self.settings.journal_path.read_bytes()
            self.assertEqual(journal, b"")
            files = [
                name
                for name in os.listdir(self.settings.data_dir)
                if name.startswith(".") and name.endswith(".tmp")
            ]
            self.assertEqual(files, [])
            self.assertTrue(self.settings.checkpoint_path.exists())
            checkpoint = json.loads(
                self.settings.checkpoint_path.read_text(encoding="utf-8")
            )
            self.assertGreaterEqual(
                checkpoint["checkpoints"][-1]["generation"],
                self._envelope()["generation"] - 2,
            )
        finally:
            state_module.JOURNAL_MAX_ENTRIES = old_entries
            state_module.JOURNAL_MAX_BYTES = old_bytes

    # ------------------------------------------------------------ 损坏
    def test_corrupt_state_degrades_without_auto_backup_promotion(self) -> None:
        self._bump(tag="a")  # 生成 .bak（generation 0）
        backup_before = self.settings.state_path.with_suffix(".json.bak").read_bytes()
        self.settings.state_path.write_bytes(b"{not json")
        store = StateStore(self.settings, self.mac_key)
        store.startup()
        self.assertTrue(store.degraded)
        self.assertEqual(
            self.settings.state_path.with_suffix(".json.bak").read_bytes(),
            backup_before,
        )
        self.assertEqual(self.settings.state_path.read_bytes(), b"{not json")
        with self.assertRaises(CorruptState):
            store.transaction(lambda body: None)

    def test_missing_state_with_backup_degrades(self) -> None:
        self._bump()
        self.settings.state_path.unlink()
        store = StateStore(self.settings, self.mac_key)
        store.startup()
        self.assertTrue(store.degraded)
        # 还有未回放的 journal 时，优先报告 journal（同样不能自动恢复）。
        self.assertIn("journal", store.degraded_reason)

        # 去掉 journal 后只剩 .bak：仍然拒绝自动提升。
        self.settings.journal_path.unlink()
        store = StateStore(self.settings, self.mac_key)
        store.startup()
        self.assertTrue(store.degraded)
        self.assertIn("bak", store.degraded_reason)

    def test_manual_backup_recovery(self) -> None:
        self._bump(tag="a")  # state gen1, bak gen0
        self.settings.state_path.write_bytes(b"garbage")
        store = StateStore(self.settings, self.mac_key)
        store.startup()
        self.assertTrue(store.degraded)
        env = store.recover_from_backup()
        self.assertEqual(env["generation"], 0)
        self.assertFalse(store.degraded)
        self.assertEqual(
            parse_envelope_bytes(
                self.mac_key, self.settings.state_path.read_bytes()
            )["generation"],
            0,
        )
        archived = [
            name
            for name in os.listdir(self.settings.backups_dir)
            if name.startswith("journal-backup-recovery-")
        ]
        self.assertEqual(len(archived), 1)

    def test_generation_regression_degrades(self) -> None:
        self._bump(tag="a")
        self._bump(tag="b")  # store 内存为 gen2
        env = self._envelope()
        regressed = seal_envelope(self.mac_key, env["body"], 1)
        self._write_envelope(regressed)
        with self.assertRaises(CorruptState):
            self.store.transaction(lambda body: None)
        self.assertTrue(self.store.degraded)

    def test_same_generation_different_body_degrades(self) -> None:
        self._bump(tag="a")
        env = self._envelope()
        body = json.loads(json.dumps(env["body"]))
        body["senders"]["other"] = {"marker": True}
        forged = seal_envelope(self.mac_key, body, env["generation"])
        self._write_envelope(forged)
        with self.assertRaises(CorruptState):
            self.store.transaction(lambda body: None)
        self.assertTrue(self.store.degraded)

    def test_two_different_mac_keys(self) -> None:
        env = self._envelope()
        with self.assertRaises(CorruptState):
            parse_envelope_bytes(os.urandom(32), json.dumps(env).encode("utf-8"))

    # ------------------------------------------------------------ 写失败
    def test_failure_after_journal_append_recovers_on_restart(self) -> None:
        with mock.patch.object(
            state_module, "replace_file", side_effect=OSError("disk full")
        ):
            with self.assertRaises(OSError):
                self._bump(tag="survives")
        # 主状态仍是 gen0，但 journal 已包含 gen1。
        self.assertEqual(self._envelope()["generation"], 0)
        store = StateStore(self.settings, self.mac_key)
        store.startup()
        self.assertEqual(store.snapshot()["generation"], 1)
        self.assertIn("survives", store.snapshot()["body"]["senders"])

    def test_second_writer_lock_is_exclusive(self) -> None:
        # Windows 的 msvcrt 字节锁属于进程：同进程第二个句柄不会冲突。真正要
        # 验证的是“第二个服务进程”，所以必须开子进程持锁。
        lock_path = str(self.settings.locks_dir / "writer.lock")
        ff_root = str(Path(__file__).resolve().parents[1])
        code = (
            "import sys, time\n"
            f"sys.path.insert(0, {ff_root!r})\n"
            "from vaultshare.storage.locking import FileLock\n"
            "FileLock(sys.argv[1], timeout=1.0).acquire()\n"
            "print('locked', flush=True)\n"
            "time.sleep(30)\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", code, lock_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual((child.stdout.readline() or "").strip(), "locked")
            with self.assertRaises(LockTimeout):
                FileLock(lock_path, timeout=0.2).acquire()
        finally:
            child.terminate()
            child.wait(timeout=10)
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()
        # 子进程释放后锁可再次获取。
        third = FileLock(lock_path, timeout=1.0).acquire()
        third.release()


if __name__ == "__main__":
    unittest.main()
