"""首次启动初始化：凭证、代理密钥、状态中的当前代理 key_id。

非交互模式（stdout 不是 TTY）绝不把初始密码/TOTP 密钥写到 stdout/stderr。
它们写入 ``data/secrets/INITIAL_CREDENTIALS.txt``（0600 / 收紧 ACL），控制台
只打印路径。管理员用 ``vaultshare admin ack-init`` 删除该文件；删除前登录页
显示告警。
"""

from __future__ import annotations

import os
import sys

from ..config import Settings
from ..errors import Conflict, Unavailable
from ..storage import permissions
from ..storage.atomic import atomic_write_bytes
from ..storage.secrets import init_secret_files
from ..storage.state import StateStore
from .auth import CredentialsStore, provisioning_uri

__all__ = ["provision", "print_initial_credentials", "InitialCredentials"]


class InitialCredentials:
    def __init__(self, settings: Settings, username: str, password: str, uri: str):
        self.settings = settings
        self.username = username
        self.password = password
        self.uri = uri


def provision(settings: Settings, store: StateStore, *, force_print: bool = False) -> InitialCredentials | None:
    """预置密钥与状态下当前代理 key。返回首次生成的凭证（若有）。"""
    init_secret_files(settings)
    from ..broker.keyring import KeyRing

    keyring = KeyRing(settings)
    keys = keyring.ensure_initial()
    current = store.snapshot()["body"]["broker"].get("current_key_id", "")
    if not current:
        def mutate(body):
            body["broker"]["current_key_id"] = keys.key_id

        store.transaction(mutate)
    elif current != keys.key_id:
        # 状态指向某把密钥；它必须存在。若不存在且尚未有包，允许切到现有密钥；
        # 否则拒绝启动，避免静默换钥导致旧包无法兑换。
        try:
            keyring.load(current)
        except Unavailable:
            has_packages = bool(store.snapshot()["body"].get("packages"))
            if has_packages:
                raise Conflict(
                    "状态引用的代理密钥缺失，拒绝启动。请先恢复密钥或人工轮换。",
                    code="broker_key_missing",
                )

            def mutate(body):
                body["broker"]["current_key_id"] = keys.key_id

            store.transaction(mutate)

    creds_store = CredentialsStore(settings)
    if creds_store.exists():
        return None
    creds, password = creds_store.create_initial()
    uri = provisioning_uri(creds)
    initial = InitialCredentials(settings, creds.username, password, uri)
    print_initial_credentials(initial, force_print=force_print)
    return initial


def print_initial_credentials(initial: InitialCredentials, *, force_print: bool = False) -> None:
    interactive = sys.stdout.isatty()
    if not interactive and not force_print:
        path = initial.settings.initial_credentials_path
        text = (
            "VaultShare 首次初始化凭证（阅读后请删除此文件）\n"
            f"用户名: {initial.username}\n"
            f"密码: {initial.password}\n"
            f"TOTP URI: {initial.uri}\n"
            "运行 `vaultshare admin ack-init` 删除本文件。\n"
        )
        atomic_write_bytes(str(path), text.encode("utf-8"))
        permissions.tighten(str(path))
        print(f"首次初始化：凭证已写入 {path}（权限已收紧）。")
        print("读取后请运行 `vaultshare admin ack-init` 删除该文件。")
        return

    print("=" * 60)
    print("VaultShare 首次初始化凭证（只显示这一次，请立即保存）")
    print(f"用户名: {initial.username}")
    print(f"密码  : {initial.password}")
    print(f"TOTP  : {initial.uri}")
    print("=" * 60)
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(initial.uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception:  # noqa: BLE001 - 二维码只是便利功能
        print("（无法在终端渲染二维码，请手动输入上面的 TOTP URI）")


def ack_init(settings: Settings) -> bool:
    path = str(settings.initial_credentials_path)
    if not os.path.exists(path):
        return False
    # 尽力覆写后删除（一次性凭证，减少残留窗口）。
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
        return True
    except OSError:
        return False
