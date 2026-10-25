"""测试夹具：临时数据目录、状态、代理、发送方身份与共享包。

本目录不使用 ``__init__.py``：``python -m unittest discover -s ff\\tests`` 会把
本目录加入 ``sys.path``，各测试模块直接 ``import support``。这里再把仓库根目录
与 ``ff/`` 加入 ``sys.path``，使 ``import vaultshare`` 可用。
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
FF_ROOT = HERE.parent
REPO_ROOT = FF_ROOT.parent
for _path in (str(REPO_ROOT), str(FF_ROOT), str(HERE)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from vaultshare.broker.keyring import KeyRing  # noqa: E402
from vaultshare.broker.service import SoftwareKeyBroker  # noqa: E402
from vaultshare.client.codes import open_sealed_code  # noqa: E402
from vaultshare.client.identity import SenderKeys  # noqa: E402
from vaultshare.config import Settings  # noqa: E402
from vaultshare.crypto import hpke  # noqa: E402
from vaultshare.crypto.keys import Ed25519Keys  # noqa: E402
from vaultshare.protocol.container import pack_directory  # noqa: E402
from vaultshare.protocol.grants import make_grant  # noqa: E402
from vaultshare.protocol.identity import (  # noqa: E402
    build_broker_identity,
    build_sender_identity,
)
from vaultshare.protocol.keyconfig import build_keyconfig  # noqa: E402
from vaultshare.protocol.policy import build_policy, policy_digest  # noqa: E402
from vaultshare.storage.atomic import read_bytes  # noqa: E402
from vaultshare.storage.audit import AuditLog  # noqa: E402
from vaultshare.storage.package_store import create_package_dir, payload_path  # noqa: E402
from vaultshare.storage.secrets import init_secret_files, read_state_mac_key  # noqa: E402
from vaultshare.storage.state import StateStore  # noqa: E402
from vaultshare.util.canonical import canonical_bytes, sha256_hex  # noqa: E402
from vaultshare.util.ids import PKG_ID_BYTES, new_hex_id  # noqa: E402
from vaultshare.util.timeutil import now  # noqa: E402

__all__ = [
    "Env",
    "PackageFixture",
    "FakeBroker",
    "make_sender",
    "make_settings",
    "write_source_tree",
    "tree_digest",
]


def make_settings(prefix: str = "vaultshare-test-") -> tuple[Settings, Path]:
    root = Path(tempfile.mkdtemp(prefix=prefix))
    settings = Settings(
        data_dir=(root / "data").resolve(),
        host="127.0.0.1",
        port=0,
        broker_host="127.0.0.1",
        broker_port=0,
        https=False,
    )
    settings.ensure_dirs()
    return settings, root


def make_sender() -> SenderKeys:
    ed = Ed25519Keys.generate()
    x_private, _x_public = hpke.generate_keypair()
    identity = build_sender_identity(
        ed.private_bytes, x_private, created_at=now()
    )
    return SenderKeys(identity, ed.private_bytes, x_private)


def write_source_tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "hello.txt").write_text("你好，VaultShare\n", encoding="utf-8")
    (root / "empty.txt").write_bytes(b"")
    sub = root / "子目录"
    sub.mkdir(exist_ok=True)
    (sub / "data.bin").write_bytes(bytes(range(256)) * 300)
    return root


def tree_digest(root: Path) -> dict[str, str]:
    result = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            result[path.relative_to(root).as_posix()] = sha256_hex(path.read_bytes())
    return result


class FakeBroker:
    """直接调用 ``SoftwareKeyBroker``，跳过 IPC 传输层。

    异常语义与真实 IPC 保持一致：代理抛出的业务异常在 IPC 客户端那边会变成
    ``IpcError(code)``，兑换状态机也据此映射。这里把同样的事情做一遍，否则
    测试会走一条生产环境不存在的异常路径。IPC 的认证与重放在 ``test_ipc.py``
    单独覆盖。
    """

    def __init__(self, service: SoftwareKeyBroker):
        self.service = service
        self.calls: list[str] = []

    def call(self, op: str, body: dict, *, request_id: str | None = None) -> dict:
        from vaultshare.errors import IpcError, VaultShareError

        self.calls.append(op)
        digest = sha256_hex(canonical_bytes(body))
        try:
            return self.service.dispatch(
                op, body, request_id or new_hex_id(32), digest
            )
        except VaultShareError as exc:
            raise IpcError(exc.message, code=exc.code) from exc


@dataclass
class PackageFixture:
    package_id: str
    policy: dict
    keyconfig: dict
    sender: SenderKeys
    codes: list[tuple[str, str]] = field(default_factory=list)

    @property
    def first_code(self) -> str:
        return self.codes[0][1]

    @property
    def first_grant_id(self) -> str:
        return self.codes[0][0]


class Env:
    """一套完整的临时服务端环境（无 HTTP）。"""

    def __init__(self, prefix: str = "vaultshare-test-"):
        self.settings, self.root = make_settings(prefix)
        init_secret_files(self.settings)
        self.audit = AuditLog(str(self.settings.audit_path))
        self.store = StateStore(
            self.settings, read_state_mac_key(self.settings), self.audit
        )
        self.store.startup()
        self.keyring = KeyRing(self.settings)
        self.keys = self.keyring.ensure_initial()
        if self.store.snapshot()["body"]["broker"].get("current_key_id") != self.keys.key_id:

            def set_key(body: dict) -> None:
                body["broker"]["current_key_id"] = self.keys.key_id

            self.store.transaction(set_key)
        self.broker_identity = build_broker_identity(
            self.keys.key_id,
            self.keys.hpke_public,
            self.keys.signing_public,
            created_at=now(),
        )
        self.broker = SoftwareKeyBroker(self.settings)
        self.fake_broker = FakeBroker(self.broker)
        self.context = SimpleNamespace(
            settings=self.settings,
            store=self.store,
            broker=self.fake_broker,
            audit=self.audit,
        )
        self._senders: dict[str, SenderKeys] = {}

    # ------------------------------------------------------------ 身份
    def register_sender(self, sender: SenderKeys) -> None:
        record = sender.identity.record

        def mutate(body: dict) -> None:
            body["senders"][sender.identity.sender_key_id] = {
                "sender_key_id": sender.identity.sender_key_id,
                "identity_hash": sender.identity.digest,
                "ed25519_public_key": record["ed25519_public_key"],
                "x25519_public_key": record["x25519_public_key"],
                "registered_at": now(),
                "revoked": False,
                "record": dict(record),
            }

        self.store.transaction(mutate)
        self._senders[sender.identity.sender_key_id] = sender

    # ------------------------------------------------------------ 包
    def create_package(
        self,
        sender: SenderKeys,
        *,
        codes: int = 1,
        max_uses: int = 1,
        expires_in: int = 3600,
        source: Path | None = None,
        package_id: str | None = None,
    ) -> PackageFixture:
        if sender.identity.sender_key_id not in self._senders:
            self.register_sender(sender)
        package_id = package_id or new_hex_id(PKG_ID_BYTES)
        source = source or write_source_tree(self.root / f"src-{package_id[:8]}")
        created = now()
        policy = build_policy(
            package_id,
            sender.identity,
            sender.ed25519_private,
            max_codes=codes,
            max_uses_per_code=max_uses,
            max_total_redemptions=codes * max_uses,
            latest_expiry=created + expires_in,
            created_at=created,
        )
        policy_hash = policy_digest(policy)
        k_pkg = bytearray(os.urandom(32))
        try:
            keyconfig = build_keyconfig(
                package_id,
                policy_hash,
                k_pkg,
                self.broker_identity,
                sender.identity,
                sender.ed25519_private,
                created_at=created,
            )
            directory = create_package_dir(
                self.settings, package_id, keyconfig, policy
            )
            result = pack_directory(
                source, payload_path(self.settings, package_id), k_pkg, package_id
            )
        finally:
            k_pkg[:] = b"\0" * len(k_pkg)

        payload_sha = sha256_hex(read_bytes(str(payload_path(self.settings, package_id))))
        payload_size = payload_path(self.settings, package_id).stat().st_size

        def mutate(body: dict) -> None:
            body["packages"][package_id] = {
                "status": "active",
                "created_at": created,
                "keyconfig_sha256": sha256_hex(canonical_bytes(keyconfig)),
                "policy_sha256": sha256_hex(canonical_bytes(policy)),
                "payload_sha256": payload_sha,
                "payload_size": payload_size,
                "broker_key_id": keyconfig["broker"]["key_id"],
                "sender_key_id": sender.identity.sender_key_id,
                "sender_identity_hash": sender.identity.digest,
            }
            body["grants_counters"][package_id] = {
                "issued": 0,
                "allocated_uses": 0,
                "used": 0,
            }

        self.store.transaction(mutate)
        self.codes: list[tuple[str, str]] = []
        fixture = PackageFixture(package_id, policy, keyconfig, sender, self.codes)
        if codes:
            self.issue(fixture, count=codes, uses=max_uses, expires_at=created + expires_in)
        return fixture

    # ------------------------------------------------------------ 授权
    def issue(
        self,
        package: PackageFixture,
        *,
        count: int = 1,
        uses: int = 1,
        expires_at: int | None = None,
        batch_id: str | None = None,
    ) -> list[tuple[str, str]]:
        batch_id = batch_id or new_hex_id(16)
        expires_at = expires_at or now() + 3600
        result = self.broker.create_grants(
            {
                "batch_id": batch_id,
                "package_id": package.package_id,
                "count": count,
                "uses_per_code": uses,
                "expires_at": expires_at,
                "policy_version": package.policy["policy_version"],
            }
        )
        records = []
        for item in result["grants"]:
            record = make_grant(
                grant_id=item["grant_id"],
                package_id=package.package_id,
                code_verifier_hex=item["code_verifier"],
                sealed_code=item["sealed_code"],
                expires_at=item["expires_at"],
                max_uses=item["max_uses"],
                policy_version=item["policy_version"],
                batch_id=item["batch_id"],
                created_at=item["created_at"],
            )
            records.append((record, item["sealed_code"]))

        def mutate(body: dict) -> None:
            for record, _sealed in records:
                body["grants"][record["grant_id"]] = record

        self.store.transaction(mutate)
        issued = []
        for record, sealed in records:
            opened = open_sealed_code(
                package.package_id,
                record["grant_id"],
                sealed,
                package.sender.x25519_private,
                package.sender.x25519_public,
            )
            issued.append((record["grant_id"], opened.code))
        package.codes.extend(issued)
        return issued

    # ------------------------------------------------------------ 清理
    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
