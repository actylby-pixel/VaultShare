"""启动密钥代理进程。"""

from __future__ import annotations

import os
import sys

from ..config import Settings, load_settings
from ..storage.atomic import cleanup_temp_files
from ..storage.locking import FileLock, LockTimeout
from ..storage.secrets import init_secret_files, read_ipc_key
from .ipc import IpcServer
from .keyring import KeyRing
from .service import SoftwareKeyBroker


def run_broker(settings: Settings) -> int:
    settings.ensure_dirs()
    init_secret_files(settings)
    cleanup_temp_files(settings.brokers_dir)
    lock_path = str(settings.locks_dir / "broker.lock")
    try:
        lock = FileLock(lock_path, timeout=0.5).acquire()
    except LockTimeout:
        print("已有另一个密钥代理在运行（broker.lock 被占用）", file=sys.stderr)
        return 2

    try:
        keyring = KeyRing(settings)
        keys = keyring.ensure_initial()
        ipc_key = read_ipc_key(settings)
        service = SoftwareKeyBroker(settings)
        server = IpcServer(settings.broker_host, settings.broker_port, ipc_key, service.dispatch)
        identity = service.get_identity()
        print(f"密钥代理已启动：{settings.broker_host}:{settings.broker_port}")
        print(f"  key_id      : {identity['key_id']}")
        print(f"  fingerprint : {identity['fingerprint']}")
        print("  请通过可信渠道核对指纹后再分发给发送方。")
        print("  注意：这是独立软件进程，不等同于 TEE；具有管理员权限的攻击者仍可能读取密钥。")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n正在停止密钥代理…")
        finally:
            server.shutdown()
        return 0
    finally:
        lock.release()


def main(argv: list[str] | None = None) -> int:
    return run_broker(load_settings())


if __name__ == "__main__":
    raise SystemExit(main())
