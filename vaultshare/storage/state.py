"""权威状态文件：``state.json`` + journal + 检查点。

不变量
======
* 状态 MAC 覆盖完整信封：``format``、``version``、``generation``、``body``。
  只 MAC ``body`` 会让版本或代数被替换而无法察觉。
* 每次事务：读盘并验 MAC → 深拷贝 → 变更 → 新 generation → 写临时文件并
  fsync → 追加 journal 并 fsync → 备份旧状态 → 原子替换 → 读回验证 →
  更新检查点 → 必要时压实 journal。
* ``used`` 只在事务成功落盘后才会增加；额度一经占用永不回滚。
* 主状态损坏或无法判定 journal 提交顺序时进入**降级模式**：禁止兑换，
  不自动提升 ``.bak``，不重置任何授权。恢复必须人工确认。
"""

from __future__ import annotations

import copy
import hmac as _hmac
import json
import os
import tempfile
from typing import Callable, Optional

from ..config import Settings
from ..errors import CorruptState
from ..util.canonical import canonical_bytes, hmac_sha256, sha256_hex
from ..version import STATE_FORMAT, PROTOCOL_VERSION
from .atomic import (
    atomic_write_bytes,
    atomic_write_json,
    fsync_dir,
    read_bytes,
    replace_file,
)
from .locking import FileLock

JOURNAL_MAX_ENTRIES = 256
JOURNAL_MAX_BYTES = 8 * 1024 * 1024
REQUIRED_BODY_KEYS = {
    "senders",
    "packages",
    "grants",
    "requests",
    "revoked_packages",
    "auth",
    "grants_counters",
    "broker",
}


def empty_body() -> dict:
    return {
        "senders": {},
        "packages": {},
        "grants": {},
        "requests": {},
        "revoked_packages": {},
        "auth": {"last_totp_step": 0, "lockouts": {}, "api_epoch": 1},
        "grants_counters": {},
        "broker": {"current_key_id": ""},
    }


def envelope_body_ok(body) -> bool:
    if not isinstance(body, dict):
        return False
    if set(body.keys()) != REQUIRED_BODY_KEYS:
        return False
    for key in ("senders", "packages", "grants", "requests", "revoked_packages", "grants_counters"):
        if not isinstance(body[key], dict):
            return False
    auth = body["auth"]
    if not isinstance(auth, dict):
        return False
    if not isinstance(auth.get("last_totp_step"), int):
        return False
    if not isinstance(auth.get("lockouts", {}), dict):
        return False
    if not isinstance(auth.get("api_epoch"), int):
        return False
    broker = body["broker"]
    return isinstance(broker, dict) and isinstance(broker.get("current_key_id"), str)


def make_envelope(body: dict, generation: int) -> dict:
    return {
        "format": STATE_FORMAT,
        "version": PROTOCOL_VERSION,
        "generation": int(generation),
        "body": copy.deepcopy(body),
    }


def mac_input(envelope: dict) -> bytes:
    """MAC 输入覆盖完整信封（不含 mac 字段）。"""
    return canonical_bytes(
        {
            "format": envelope["format"],
            "version": envelope["version"],
            "generation": envelope["generation"],
            "body": envelope["body"],
        }
    )


def compute_mac(mac_key: bytes, envelope: dict) -> str:
    return hmac_sha256(mac_key, mac_input(envelope)).hex()


def envelope_digest(envelope: dict) -> str:
    """预授权票据中 ``state_digest`` 的定义：**完整状态信封**的 SHA-256。"""
    return sha256_hex(canonical_bytes(envelope))


def seal_envelope(mac_key: bytes, body: dict, generation: int) -> dict:
    env = make_envelope(body, generation)
    env["mac"] = compute_mac(mac_key, env)
    return env


def verify_envelope(mac_key: bytes, envelope: dict) -> None:
    if not isinstance(envelope, dict):
        raise CorruptState("状态不是 JSON 对象")
    if envelope.get("format") != STATE_FORMAT:
        raise CorruptState("状态格式标识不匹配")
    if envelope.get("version") != PROTOCOL_VERSION:
        raise CorruptState("不支持的状态版本")
    generation = envelope.get("generation")
    if not isinstance(generation, int) or generation < 0:
        raise CorruptState("状态 generation 非法")
    if not envelope_body_ok(envelope.get("body")):
        raise CorruptState("状态 body 结构非法")
    mac = envelope.get("mac")
    if not isinstance(mac, str) or len(mac) != 64:
        raise CorruptState("状态缺少 MAC 或长度非法")
    expected = compute_mac(mac_key, envelope)
    if not _hmac.compare_digest(expected, mac):
        raise CorruptState("状态 MAC 不匹配")


def parse_envelope_bytes(mac_key: bytes, raw: bytes) -> dict:
    try:
        env = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptState("状态文件不是合法 UTF-8 JSON") from exc
    verify_envelope(mac_key, env)
    return env


def read_verified_state(path: str, mac_key: bytes) -> dict:
    """供代理只读校验使用。"""
    try:
        raw = read_bytes(path)
    except OSError as exc:
        raise CorruptState("无法读取状态文件") from exc
    return parse_envelope_bytes(mac_key, raw)


class StateStore:
    def __init__(
        self,
        settings: Settings,
        mac_key: bytes,
        audit: Optional[Callable[..., None]] = None,
    ):
        self.settings = settings
        self.mac_key = bytes(mac_key)
        self.audit = audit or (lambda *a, **k: None)
        self._envelope: Optional[dict] = None
        self.degraded = False
        self.degraded_reason = ""
        self._lock_path = settings.locks_dir / "state.lock"
        self._thread_lock = __import__("threading").RLock()

    # ------------------------------------------------------------ 生命周期
    @property
    def generation(self) -> int:
        return int(self._envelope["generation"]) if self._envelope else -1

    @property
    def body(self) -> dict:
        if self._envelope is None:
            raise CorruptState("状态尚未加载")
        return self._envelope["body"]

    def startup(self) -> None:
        """加载/恢复状态。

        整个启动过程都持有状态文件锁：``_cleanup_temp`` 会删除 ``*.tmp``，
        若与另一个进程的原子写并发，就会删掉对方正在写入的临时文件。生产
        环境本来只有一个写者，但测试与误启动的第二实例不该因此损坏状态。
        """
        self.settings.ensure_dirs()
        with FileLock(str(self._lock_path), timeout=20.0):
            self._startup_locked()

    def _startup_locked(self) -> None:
        self._cleanup_temp()
        state_path = str(self.settings.state_path)
        journal_path = str(self.settings.journal_path)

        if not os.path.exists(state_path):
            if os.path.exists(journal_path) and os.path.getsize(journal_path) > 0:
                self._enter_degraded("主状态文件缺失，但存在未回放的 journal")
                return
            if os.path.exists(str(self.settings.state_path) + ".bak"):
                self._enter_degraded("主状态文件缺失，存在 .bak 但不自动提升")
                return
            env = seal_envelope(self.mac_key, empty_body(), 0)
            self._write_state_file(env, strict=False)
            self._envelope = env
            self._write_checkpoint()
            self.audit("state_initialized", generation=0)
            return

        try:
            env = parse_envelope_bytes(self.mac_key, read_bytes(state_path))
        except CorruptState as exc:
            self._enter_degraded(str(exc))
            return

        self._envelope = env
        try:
            recovered = self._replay_journal(env, journal_path)
        except CorruptState as exc:
            self._enter_degraded(str(exc))
            return

        if recovered is not None and recovered["generation"] > env["generation"]:
            # 回放成功：把恢复后的状态落盘，再继续服务。journal 条目本身已 fsync。
            self._write_state_file(recovered, strict=True)
            self._envelope = recovered
            self.audit(
                "state_recovered",
                generation=recovered["generation"],
                previous=env["generation"],
            )
        self._write_checkpoint()
        self._maybe_compact()

    def _enter_degraded(self, reason: str) -> None:
        self.degraded = True
        self.degraded_reason = reason
        self._envelope = None
        self.audit("state_corrupt", reason=reason)

    def _cleanup_temp(self) -> None:
        try:
            for name in os.listdir(self.settings.data_dir):
                if name.startswith(".") and name.endswith(".tmp"):
                    try:
                        os.remove(self.settings.data_dir / name)
                    except OSError:
                        pass
        except OSError:
            pass

    # ------------------------------------------------------------ 事务
    def transaction(self, mutator: Callable, *, with_generation: bool = False) -> object:
        """串行事务。``mutator`` 抛异常即放弃，不产生任何落盘副作用。

        ``with_generation=True`` 时调用 ``mutator(body, generation)``，
        ``generation`` 是本次变更将要写入的代数。预留记录需要把“提交时的
        generation”绑定进状态，所以必须由存储层告知，而不是调用方猜。
        """
        with self._thread_lock:
            if self.degraded:
                raise CorruptState(self.degraded_reason or "状态处于降级模式")
            with FileLock(str(self._lock_path), timeout=20.0):
                base = self._reload_locked()
                body = copy.deepcopy(base["body"])
                new_generation = base["generation"] + 1
                result = (
                    mutator(body, new_generation)
                    if with_generation
                    else mutator(body)
                )
                new_env = seal_envelope(self.mac_key, body, new_generation)
                self._commit(base, new_env)
                self._maybe_compact()
                return result

    def _reload_locked(self) -> dict:
        """事务开始时重新读盘；绝不信任可能被外部替换的内存副本。"""
        try:
            env = parse_envelope_bytes(
                self.mac_key, read_bytes(str(self.settings.state_path))
            )
        except CorruptState:
            self._enter_degraded("事务读盘校验失败")
            raise
        if self._envelope is not None:
            if env["generation"] < self._envelope["generation"]:
                self._enter_degraded("检测到 generation 倒退")
                raise CorruptState("状态 generation 倒退")
            if env["generation"] == self._envelope["generation"] and canonical_bytes(
                env["body"]
            ) != canonical_bytes(self._envelope["body"]):
                self._enter_degraded("同一 generation 出现不同内容")
                raise CorruptState("同一 generation 内容不一致")
        return env

    def _commit(self, base: dict, new_env: dict) -> None:
        path = str(self.settings.state_path)
        data = json.dumps(
            new_env, ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state.json.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self._append_journal(new_env)
            # 备份旧状态（仅在旧文件合法时）。备份失败不阻止主流程，但必须审计。
            try:
                atomic_write_bytes(path + ".bak", read_bytes(path))
            except OSError as exc:
                self.audit("disk_error", operation="backup", error=str(exc))
            replace_file(tmp, path)
            fsync_dir(directory)
            back = read_bytes(path)
            if back != data:
                raise OSError("状态替换后读回校验失败")
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        self._envelope = new_env
        self._write_checkpoint()

    def _append_journal(self, env: dict) -> None:
        line = canonical_bytes(env) + b"\n"
        with open(self.settings.journal_path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def _write_state_file(self, env: dict, strict: bool = True) -> None:
        atomic_write_json(str(self.settings.state_path), env, indent=2)

    # ------------------------------------------------------------ journal
    def _read_journal(self) -> list[dict]:
        path = self.settings.journal_path
        if not os.path.exists(path):
            return []
        raw = read_bytes(path)
        if not raw:
            return []
        lines = raw.split(b"\n")
        entries: list[dict] = []
        trailing_partial = raw.endswith(b"\n") is False
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            is_last = index == len(lines) - 1
            try:
                env = json.loads(line.decode("utf-8"))
                verify_envelope(self.mac_key, env)
            except (UnicodeDecodeError, json.JSONDecodeError, CorruptState) as exc:
                if is_last and trailing_partial:
                    # 崩溃留下的半行：尚未提交，忽略。
                    break
                raise CorruptState(f"journal 第 {index + 1} 行损坏") from exc
            entries.append(env)
        return entries

    def _replay_journal(self, base: dict, journal_path: str) -> Optional[dict]:
        try:
            entries = self._read_journal()
        except CorruptState:
            raise
        current = base
        for env in entries:
            if env["generation"] <= current["generation"]:
                if env["generation"] == current["generation"] and canonical_bytes(
                    env["body"]
                ) != canonical_bytes(current["body"]):
                    raise CorruptState("journal 与主状态在同一 generation 内容不同")
                continue
            if env["generation"] != current["generation"] + 1:
                raise CorruptState("journal generation 不连续")
            current = env
        return current if current["generation"] > base["generation"] else None

    def _maybe_compact(self) -> None:
        path = self.settings.journal_path
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            return
        count = 0
        try:
            if size > 0:
                with open(path, "rb") as f:
                    count = sum(1 for _ in f)
        except OSError:
            return
        if size <= JOURNAL_MAX_BYTES and count <= JOURNAL_MAX_ENTRIES:
            return
        self._compact()

    def _compact(self) -> None:
        """只保留 generation > 当前已提交代的条目（正常为空）。"""
        current = self._envelope["generation"] if self._envelope else -1
        entries = self._read_journal()
        keep = [e for e in entries if e["generation"] > current]
        payload = b"".join(canonical_bytes(e) + b"\n" for e in keep)
        atomic_write_bytes(str(self.settings.journal_path), payload)
        self._write_checkpoint()

    def _write_checkpoint(self) -> None:
        if self._envelope is None:
            return
        state_bytes = read_bytes(str(self.settings.state_path))
        from ..util.timeutil import now

        entry = {
            "generation": self._envelope["generation"],
            "state_sha256": sha256_hex(state_bytes),
            "at": now(),
        }
        history = []
        if os.path.exists(self.settings.checkpoint_path):
            try:
                old = json.loads(read_bytes(str(self.settings.checkpoint_path)))
                history = list(old.get("checkpoints", []))
            except (OSError, json.JSONDecodeError):
                history = []
        if not history or history[-1].get("generation") != entry["generation"]:
            history.append(entry)
        history = history[-2:]
        atomic_write_json(
            str(self.settings.checkpoint_path),
            {
                "format": "vaultshare-journal-checkpoint",
                "version": 1,
                "checkpoints": history,
            },
        )

    # ------------------------------------------------------------ 只读
    def snapshot(self) -> dict:
        """当前内存快照（含 mac）。调用方不得修改。"""
        if self._envelope is None:
            raise CorruptState(self.degraded_reason or "状态不可用")
        return self._envelope

    def display_state(self) -> dict:
        if self._envelope is None:
            return {"degraded": True, "reason": self.degraded_reason}
        return {
            "degraded": self.degraded,
            "generation": self._envelope["generation"],
            "body": copy.deepcopy(self._envelope["body"]),
        }

    # ------------------------------------------------------------ 人工恢复
    def recover_from_journal(self) -> dict:
        """人工确认后从 journal 恢复。失败抛 CorruptState，不写任何文件。"""
        base = parse_envelope_bytes(
            self.mac_key, read_bytes(str(self.settings.state_path))
        )
        recovered = self._replay_journal(base, str(self.settings.journal_path))
        if recovered is None:
            raise CorruptState("journal 中没有可恢复的更新")
        self._write_state_file(recovered)
        self._envelope = recovered
        self.degraded = False
        self.degraded_reason = ""
        self.audit("state_recovered", generation=recovered["generation"], manual=True)
        self._compact()
        self._write_checkpoint()
        return recovered

    def recover_from_backup(self) -> dict:
        """人工确认后从 ``state.json.bak`` 恢复。

        这是**显式**操作：自动提升备份会让一次外部替换变成“看起来正常的回滚”。
        恢复后 journal 中比备份更新的条目属于被放弃的“未来”，先归档再清空；
        否则下次启动会把它们重新回放，等于恢复失败。
        """
        backup = str(self.settings.state_path) + ".bak"
        env = parse_envelope_bytes(self.mac_key, read_bytes(backup))
        self._archive_journal("backup-recovery")
        self._write_state_file(env)
        self._envelope = env
        self.degraded = False
        self.degraded_reason = ""
        self.audit("state_recovered", generation=env["generation"], manual=True, source="backup")
        self._write_checkpoint()
        return env

    def _archive_journal(self, tag: str) -> None:
        from ..util.timeutil import now

        path = self.settings.journal_path
        if not os.path.exists(path):
            return
        target = self.settings.backups_dir / f"journal-{tag}-{now()}.jsonl"
        self.settings.backups_dir.mkdir(parents=True, exist_ok=True)
        replace_file(str(path), str(target))
        fsync_dir(str(self.settings.backups_dir))
