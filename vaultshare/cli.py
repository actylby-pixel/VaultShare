"""VaultShare 统一命令行入口。

    vaultshare server run | broker run | broker info | broker rotate
    vaultshare identity init|show|register
    vaultshare encrypt|pack|upload|codes|redeem
    vaultshare admin status|backup|recover|passwd|ack-init

部署时用 ``python -m vaultshare.cli``（在 ``ff/`` 目录内或设置 PYTHONPATH）。
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
import time
from pathlib import Path

from .client.http import ApiError, HttpClient
from .client.identity import (
    SenderKeys,
    create_identity,
    identity_fingerprint,
    load_identity,
    password_from_env,
)
from .client.pack import encrypt_package, load_broker_identity, pack_package
from .client.redeem import redeem_package
from .config import Settings, load_settings
from .errors import VaultShareError
from .protocol.identity import verify_broker_identity, verify_sender_identity
from .storage import permissions
from .storage.atomic import atomic_write_bytes
from .storage.audit import AuditLog
from .storage.locking import FileLock, LockTimeout
from .storage.secrets import init_secret_files, read_state_mac_key
from .storage.state import StateStore, parse_envelope_bytes
from .util.canonical import canonical_bytes, sha256_hex
from .util.timeutil import format_iso
from .version import __version__

__all__ = ["main"]


# ------------------------------------------------------------------ 公共
def _fail(message: str, code: int = 1) -> int:
    print(f"错误：{message}", file=sys.stderr)
    return code


def _login(server: str, args) -> HttpClient:
    username = getattr(args, "username", None) or os.environ.get("VAULTSHARE_USERNAME") or "admin"
    password = getattr(args, "password", None) or os.environ.get("VAULTSHARE_PASSWORD")
    if password is None:
        password = getpass.getpass(f"{username} 的密码：")
    totp = getattr(args, "totp", None)
    if not totp:
        totp = input("6 位动态验证码：").strip()
    client = HttpClient(server, ca_file=getattr(args, "ca_file", None))
    response = client.post(
        "/api/v1/login", {"username": username, "password": password, "totp": totp}
    )
    client.token = response["token"]
    print(f"已登录：{response['username']}（token 有效至 {format_iso(response['expires'])}）")
    return client


def _register_identity(client: HttpClient, keys: SenderKeys) -> dict:
    return client.post("/api/v1/identity", keys.identity.record)


def _add_identity_auth(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--server", required=True, help="服务器地址，例如 https://host")
    parser.add_argument(
        "--ca-file",
        help="只信任该 PEM 证书/CA（自签名部署用）；设置后不信任系统根证书",
    )
    parser.add_argument("--username", help="用户名（默认 admin）")
    parser.add_argument("--password", help="密码（不推荐；优先环境变量 VAULTSHARE_PASSWORD）")
    parser.add_argument("--totp", help="6 位动态验证码（不推荐；交互输入更安全）")


def _identity_password(args) -> str | None:
    return getattr(args, "identity_password", None) or password_from_env()


# ------------------------------------------------------------------ server
def cmd_server_run(args) -> int:
    from .server.app import create_app

    settings = load_settings()
    host = args.host or settings.host
    port = args.port or settings.port
    if args.print_init_secrets and sys.stdout.isatty():
        print("提示：终端模式下本来就会打印初始凭证。")
    app = create_app(force_print_credentials=args.print_init_secrets)
    if settings.https:
        print(f"VaultShare 服务监听于 http://{host}:{port}，VAULTSHARE_HTTPS=1（TLS 由反向代理终结）。")
        print("  会话 Cookie 带 Secure 标记：请通过 https:// 域名访问；")
        print("  直接用 http:// 访问时浏览器不会保存 Cookie，登录会提示页面已过期。")
    else:
        print(f"VaultShare 服务启动于 http://{host}:{port}")
    try:
        from waitress import serve
    except ImportError:
        print("未安装 waitress，使用 Flask 内置服务器（仅建议本地测试）。", file=sys.stderr)
        app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        serve(app, host=host, port=port, threads=8)
    return 0


# ------------------------------------------------------------------ broker
def cmd_broker_run(args) -> int:
    from .broker.main import run_broker

    return run_broker(load_settings())


def cmd_broker_info(args) -> int:
    client = HttpClient(args.server, ca_file=args.ca_file)
    response = client.get("/api/v1/broker")
    record = response.get("identity")
    identity = verify_broker_identity(record, expected_fingerprint=args.fingerprint)
    out = Path(args.out)
    atomic_write_bytes(str(out), canonical_bytes(record))
    print(f"已获取代理身份：key_id={identity.key_id}")
    print(f"fingerprint : {identity.fingerprint}")
    if args.fingerprint:
        print("指纹与 --fingerprint 一致。")
    else:
        print("警告：未提供 --fingerprint。请通过可信渠道核对上面的指纹后再使用。")
    print(f"已写入 {out}")
    return 0


def cmd_broker_rotate(args) -> int:
    from .broker.keyring import KeyRing

    settings = load_settings()
    init_secret_files(settings)
    store = StateStore(settings, read_state_mac_key(settings),
                       AuditLog(str(settings.audit_path)))
    old = _read_current_key_id(settings)
    keys = KeyRing(settings).generate()

    def mutate(body):
        body["broker"]["current_key_id"] = keys.key_id

    store.transaction(mutate)
    store.audit("key_rotated", old_key_id=old, new_key_id=keys.key_id)
    print(f"代理密钥已轮换：{old or '(none)'} → {keys.key_id}")
    print("旧密钥文件保留；所有引用旧 key_id 的包仍可兑换，直至其过期或撤销。")
    return 0


def _read_current_key_id(settings: Settings) -> str:
    try:
        env = parse_envelope_bytes(
            read_state_mac_key(settings), settings.state_path.read_bytes()
        )
        return str(env["body"].get("broker", {}).get("current_key_id") or "")
    except Exception:  # noqa: BLE001
        return ""


# ------------------------------------------------------------------ identity
def cmd_identity_init(args) -> int:
    keys = create_identity(
        args.path, password=_identity_password(args)
    )
    print(f"已生成发送方身份：{keys.identity.sender_key_id}")
    print(f"身份指纹（TOFU 用）：{identity_fingerprint(keys)}")
    print(f"公钥记录：{args.path}.json")
    print(f"加密私钥：{args.path}.key")
    return 0


def cmd_identity_show(args) -> int:
    path = Path(f"{args.path}.json")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        identity = verify_sender_identity(record)
    except Exception as exc:  # noqa: BLE001
        return _fail(f"无法读取身份：{exc}")
    print(f"sender_key_id : {identity.sender_key_id}")
    print(f"fingerprint   : {identity.digest}")
    print(f"Ed25519 公钥  : {record['ed25519_public_key']}")
    print(f"X25519 公钥   : {record['x25519_public_key']}")
    return 0


def cmd_identity_register(args) -> int:
    keys = load_identity(args.path, password=_identity_password(args))
    client = _login(args.server, args)
    summary = _register_identity(client, keys)
    print(f"身份已注册：{summary['identity']['sender_key_id']}")
    return 0


# ------------------------------------------------------------------ pack / upload
def cmd_pack(args) -> int:
    broker = load_broker_identity(
        args.broker_identity, trusted_fingerprint=args.broker_fingerprint
    )
    keys = load_identity(args.identity, password=_identity_password(args))
    info = pack_package(
        args.src,
        args.out,
        keys,
        broker,
        codes=args.codes,
        max_uses=args.max_uses,
        expires=args.expires,
        server_url=args.server or "",
        require_sender_fingerprint=args.require_sender_fingerprint,
    )
    print("打包完成（已在本地完整解密校验）：")
    print(f"  package_id : {info.package_id}")
    print(f"  输出目录   : {info.out_dir}")
    if args.server:
        print(f"  服务器提示 : {args.server.rstrip('/')}")
    print(f"  文件数     : {info.manifest_files}（{info.manifest_bytes} 字节明文）")
    print(f"  密文大小   : {info.payload_size} 字节")
    print(f"  payload sha: {info.payload_sha256}")
    print(f"  代理指纹   : {broker.fingerprint}")
    return 0


def cmd_encrypt(args) -> int:
    keys = load_identity(args.identity, password=_identity_password(args))
    info = encrypt_package(
        args.src,
        args.out,
        keys,
        server_url=args.server,
        require_sender_fingerprint=args.require_sender_fingerprint,
    )
    print("加密完成（已用 K_pkg 在本地完整校验容器）：")
    print(f"  package_id : {info.package_id}")
    print(f"  输出目录   : {info.out_dir}")
    print(f"  加密容器   : {Path(info.out_dir) / 'payload.vspk'}")
    print(f"  上传凭据   : {info.upload_key_path}")
    print(f"  包信息     : {Path(info.out_dir) / 'package.json'}")
    print(f"  服务器提示 : {info.server_url}")
    print(f"  发送方指纹 : {info.sender_fingerprint}")
    print(f"  文件数     : {info.manifest_files}（{info.manifest_bytes} 字节明文）")
    print(f"  密文大小   : {info.payload_size} 字节")
    print()
    print("把 payload.vspk 交给接收方；upload-key.json 留在本机用于上传。")
    print("上传时再决定口令数量、次数与有效期；还需要发送方身份文件和代理身份文件。")
    return 0


def _broker_for_upload(args):
    if args.broker_identity:
        return load_broker_identity(
            args.broker_identity, trusted_fingerprint=args.broker_fingerprint
        )
    response = HttpClient(
        args.server, ca_file=getattr(args, "ca_file", None)
    ).get("/api/v1/broker")
    identity = verify_broker_identity(
        response.get("identity"), expected_fingerprint=args.broker_fingerprint
    )
    if not args.broker_fingerprint:
        print(
            "警告：未提供 --broker-fingerprint，代理身份未经带外核对。"
            "建议先用 broker info 核对并保存文件，再用 --broker-identity 上传。"
        )
    return identity


def cmd_upload(args) -> int:
    from .client.share import ensure_share_ready, upload_package

    keys = load_identity(args.identity, password=_identity_password(args))
    package_dir = Path(args.package)
    if (package_dir / "upload-key.json").is_file():
        ready = (package_dir / "keyconfig.json").is_file() and (
            package_dir / "policy.json"
        ).is_file()
        broker = None if ready else _broker_for_upload(args)
        ensure_share_ready(
            package_dir,
            keys,
            broker,
            codes=args.codes,
            max_uses=args.max_uses,
            expires=args.expires,
            expected_server=args.server,
        )
        if not ready:
            print("已按上传时的选择生成 KeyConfig/Policy。")
    client = _login(args.server, args)
    mode = "local" if args.local_payload else "server"
    result = upload_package(client, args.package, keys, payload_mode=mode)
    if result.created:
        print(f"已创建包 {result.package_id}")
    else:
        print(f"包已存在，继续（{result.package_id}）")
    if mode == "local":
        print("本地交付：密文未上传；请自行把 payload.vspk 交给接收方。")
    else:
        print("服务器交付：密文已上传，接收方凭口令下载。")
    print(f"已创建 {len(result.codes)} 个口令（batch {result.batch_id}）")
    print()
    print("口令（仅在本机解封；请通过安全渠道交给接收方）：")
    for item in result.codes:
        print(
            f"  {item.formatted}  grant={item.grant_id[:12]}…  "
            f"次数 {item.used}/{item.max_uses}  "
            f"到期 {format_iso(item.expires_at)}"
        )
    if args.card:
        from .client.share_card import build_card, write_card

        card = build_card(
            package_id=result.package_id,
            server=result.server or args.server,
            sender_fingerprint=keys.identity.digest,
            broker_fingerprint=result.broker_fingerprint,
            code=result.codes[0].formatted if args.card_include_code else None,
        )
        write_card(args.card, card)
        print(f"分享卡片已写入：{args.card}")
    print()
    return 0


def _print_codes(client: HttpClient, package_id: str, keys: SenderKeys) -> None:
    from .client.codes import open_sealed_code

    response = client.get(f"/api/v1/packages/{package_id}/codes")
    grants = response.get("grants") or []
    if not grants:
        print("没有口令。")
        return
    print()
    print("口令（仅在本机解封；请通过安全渠道交给接收方）：")
    for grant in grants:
        try:
            sealed = open_sealed_code(
                package_id,
                grant["grant_id"],
                grant.get("sealed_code") or {},
                keys.x25519_private,
                keys.identity.x25519_public,
            )
            code_text = sealed.formatted
        except VaultShareError as exc:
            code_text = f"(无法解开：{exc.message})"
        print(
            f"  {code_text}  grant={grant['grant_id'][:12]}…  "
            f"次数 {grant['used']}/{grant['max_uses']}  "
            f"到期 {format_iso(grant['expires_at'])}"
        )
    print()


def cmd_codes(args) -> int:
    keys = load_identity(args.identity, password=_identity_password(args))
    client = _login(args.server, args)
    _print_codes(client, args.package, keys)
    return 0


# ------------------------------------------------------------------ redeem
def cmd_redeem(args) -> int:
    client = HttpClient(args.server, ca_file=args.ca_file)
    result = redeem_package(
        client,
        args.package,
        args.code,
        args.out,
        sender_fingerprint=args.sender_fingerprint,
        broker_fingerprint=args.broker_fingerprint,
        local_payload=args.container,
    )
    print("兑换成功：")
    print(f"  请求 ID     : {result.request_id}")
    print(f"  输出目录    : {result.output_dir}")
    print(f"  文件数      : {result.manifest.get('total_files')}")
    print(f"  明文大小    : {result.manifest.get('total_bytes')} 字节")
    print(f"  发送方指纹  : {result.sender_fingerprint}")
    print(f"  代理指纹    : {result.broker_fingerprint}")
    return 0


# ------------------------------------------------------------------ admin
def cmd_admin_status(args) -> int:
    settings = load_settings()
    try:
        env = parse_envelope_bytes(
            read_state_mac_key(settings), settings.state_path.read_bytes()
        )
    except Exception as exc:  # noqa: BLE001
        print(f"状态不可用（降级）：{exc}")
        return 1
    body = env["body"]
    print(f"generation : {env['generation']}")
    print(f"状态文件   : {settings.state_path}")
    print(f"包数量     : {len(body.get('packages') or {})}")
    print(f"授权数量   : {len(body.get('grants') or {})}")
    print(f"请求记录   : {len(body.get('requests') or {})}")
    print(f"发送方身份 : {len(body.get('senders') or {})}")
    print(f"当前代理键 : {body.get('broker', {}).get('current_key_id')}")
    from .broker.ipc import IpcClient
    from .storage.secrets import read_ipc_key

    try:
        health = IpcClient(settings.broker_host, settings.broker_port, read_ipc_key(settings)).call(
            "health", {}
        )
        print(f"代理健康   : {health.get('status')} key_id={health.get('key_id')}")
    except Exception as exc:  # noqa: BLE001
        print(f"代理健康   : 不可用（{type(exc).__name__}）")
    return 0


def cmd_admin_backup(args) -> int:
    settings = load_settings()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = settings.backups_dir / stamp
    target.mkdir(parents=True, exist_ok=False)
    permissions.tighten(str(target), directory=True)
    copied = []
    for name in (
        settings.state_path,
        Path(str(settings.state_path) + ".bak"),
        settings.journal_path,
        settings.checkpoint_path,
        settings.audit_path,
        settings.credentials_path,
    ):
        if name.exists():
            destination = target / name.name
            shutil.copy2(name, destination)
            permissions.tighten(str(destination))
            copied.append(name.name)
    print(f"已备份 {len(copied)} 个文件到 {target}")
    print("注意：备份包含 TOTP 密钥与状态；请按敏感文件保管。")
    return 0


def cmd_admin_recover(args) -> int:
    if not args.confirm:
        return _fail("恢复操作必须显式加 --confirm")
    settings = load_settings()
    try:
        lock = FileLock(str(settings.locks_dir / "writer.lock"), timeout=0.5).acquire()
    except LockTimeout:
        return _fail("服务似乎仍在运行（writer.lock 被占用），请先停止服务")
    try:
        store = StateStore(settings, read_state_mac_key(settings),
                           AuditLog(str(settings.audit_path)))
        if args.from_journal:
            env = store.recover_from_journal()
        elif args.from_backup:
            env = store.recover_from_backup()
        else:
            return _fail("必须选择 --from-journal 或 --from-backup")
        print(f"已恢复：generation={env['generation']}")
        print("请重新启动服务并核对包与授权状态。")
        return 0
    finally:
        lock.release()


def cmd_admin_passwd(args) -> int:
    settings = load_settings()
    init_secret_files(settings)
    from .server.auth import Credentials, CredentialsStore, verify_password
    from werkzeug.security import generate_password_hash

    store = CredentialsStore(settings)
    creds = store.load()
    old = args.old_password or getpass.getpass("当前密码：")
    if not verify_password(creds, old):
        return _fail("当前密码不正确")
    new = args.new_password or getpass.getpass("新密码：")
    if not args.new_password and getpass.getpass("再次输入新密码：") != new:
        return _fail("两次输入不一致")
    if len(new) < 12:
        return _fail("新密码至少 12 个字符")
    store.save(
        Credentials(
            username=creds.username,
            password_hash=generate_password_hash(new, method="scrypt"),
            totp_secret=creds.totp_secret,
            created_at=creds.created_at,
        )
    )
    state = StateStore(settings, read_state_mac_key(settings),
                       AuditLog(str(settings.audit_path)))

    def mutate(body):
        body["auth"]["api_epoch"] = int(body["auth"].get("api_epoch", 1)) + 1

    state.transaction(mutate)
    state.audit("password_changed", username=creds.username)
    print("密码已更新；所有旧 Bearer token 已失效。")
    return 0


def cmd_admin_ack_init(args) -> int:
    from .server.provision import ack_init

    settings = load_settings()
    removed = ack_init(settings)
    print("已删除一次性初始凭证文件。" if removed else "没有找到待删除的初始凭证文件。")
    return 0


# ------------------------------------------------------------------ 解析器
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultshare", description="VaultShare v1 命令行")
    parser.add_argument("--version", action="version", version=f"VaultShare {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    server = sub.add_parser("server", help="服务端")
    server_sub = server.add_subparsers(dest="server_command", required=True)
    run = server_sub.add_parser("run", help="启动 Flask 服务")
    run.add_argument("--host", help="监听地址（默认取配置）")
    run.add_argument("--port", type=int, help="监听端口（默认取配置）")
    run.add_argument("--print-init-secrets", action="store_true",
                     help="非 TTY 下也把初始凭证打印到控制台（不推荐）")
    run.set_defaults(func=cmd_server_run)

    broker = sub.add_parser("broker", help="密钥代理")
    broker_sub = broker.add_subparsers(dest="broker_command", required=True)
    brun = broker_sub.add_parser("run", help="启动代理进程")
    brun.set_defaults(func=cmd_broker_run)
    binfo = broker_sub.add_parser("info", help="通过服务器取得代理身份并核对指纹")
    binfo.add_argument("--server", required=True)
    binfo.add_argument(
        "--ca-file",
        help="只信任该 PEM 证书/CA（自签名部署用）；设置后不信任系统根证书",
    )
    binfo.add_argument("--fingerprint", help="可信渠道取得的 SHA-256 指纹")
    binfo.add_argument("--out", required=True, help="写入 broker-identity.json")
    binfo.set_defaults(func=cmd_broker_info)
    brotate = broker_sub.add_parser("rotate", help="生成并启用新的代理密钥")
    brotate.set_defaults(func=cmd_broker_rotate)

    identity = sub.add_parser("identity", help="发送方身份")
    identity_sub = identity.add_subparsers(dest="identity_command", required=True)
    iinit = identity_sub.add_parser("init", help="生成新的发送方身份")
    iinit.add_argument("--path", required=True, help="身份文件前缀，例如 sender")
    iinit.add_argument("--identity-password", help="私钥口令（优先环境变量）")
    iinit.set_defaults(func=cmd_identity_init)
    ishow = identity_sub.add_parser("show", help="显示公钥身份与指纹")
    ishow.add_argument("--path", required=True)
    ishow.set_defaults(func=cmd_identity_show)
    ireg = identity_sub.add_parser("register", help="注册身份到服务器")
    ireg.add_argument("--path", required=True)
    ireg.add_argument("--identity-password")
    _add_identity_auth(ireg)
    ireg.set_defaults(func=cmd_identity_register)

    pack = sub.add_parser("pack", help="打包文件或目录为加密共享包")
    pack.add_argument("src", help="要打包的文件或目录")
    pack.add_argument("--identity", required=True)
    pack.add_argument("--identity-password")
    pack.add_argument("--broker-identity", required=True,
                      help="经 broker info 核对后保存的代理身份文件")
    pack.add_argument("--broker-fingerprint", help="额外的可信代理指纹")
    pack.add_argument("--out", required=True)
    pack.add_argument("--server", help="写入容器的服务器地址提示（便于接收方免输入）")
    pack.add_argument("--codes", type=int, default=1)
    pack.add_argument("--max-uses", type=int, default=1)
    pack.add_argument("--expires", default="7d")
    pack.add_argument(
        "--no-require-sender-fingerprint",
        dest="require_sender_fingerprint",
        action="store_false",
        help="不要求接收方核对发送方指纹（默认要求）",
    )
    pack.set_defaults(func=cmd_pack, require_sender_fingerprint=True)

    encrypt = sub.add_parser(
        "encrypt", help="只加密文件或目录，生成容器与上传凭据（不联网）"
    )
    encrypt.add_argument("src", help="要加密的文件或目录")
    encrypt.add_argument("--identity", required=True)
    encrypt.add_argument("--identity-password")
    encrypt.add_argument("--out", required=True,
                         help="输出目录（可以已存在，只要没有同名产物）")
    encrypt.add_argument("--server", required=True,
                         help="写入容器的服务器地址（接收方自动填入）")
    encrypt.add_argument(
        "--no-require-sender-fingerprint",
        dest="require_sender_fingerprint",
        action="store_false",
        help="不要求接收方核对发送方指纹（默认要求）",
    )
    encrypt.set_defaults(func=cmd_encrypt, require_sender_fingerprint=True)

    upload = sub.add_parser("upload", help="上传打包目录并创建/领取口令")
    upload.add_argument("package", help="pack 或 encrypt 的输出目录")
    upload.add_argument(
        "--local-payload",
        action="store_true",
        help="不上传密文：服务器只保存元数据与口令，接收方使用发送方直接交付的容器",
    )
    upload.add_argument("--identity", required=True)
    upload.add_argument("--identity-password")
    _add_identity_auth(upload)
    upload.add_argument("--broker-identity",
                        help="代理身份文件（生成分享策略时需要）")
    upload.add_argument("--broker-fingerprint",
                        help="可信代理指纹；未提供时会警告")
    upload.add_argument("--codes", type=int, default=1,
                        help="口令数量（仅对 encrypt 的包生效）")
    upload.add_argument("--max-uses", type=int, default=1,
                        help="每个口令可用次数（仅对 encrypt 的包生效）")
    upload.add_argument("--expires", default="7d",
                        help="有效期，例如 12h/7d（仅对 encrypt 的包生效）")
    upload.add_argument("--card", help="上传后写出分享卡片 JSON 的路径")
    upload.add_argument("--card-include-code", action="store_true",
                        help="在分享卡片中附上第一个口令（卡片即凭证）")
    upload.set_defaults(func=cmd_upload)

    codes = sub.add_parser("codes", help="查看并解封已有口令")
    codes.add_argument("--package", required=True)
    codes.add_argument("--identity", required=True)
    codes.add_argument("--identity-password")
    _add_identity_auth(codes)
    codes.set_defaults(func=cmd_codes)

    redeem = sub.add_parser("redeem", help="兑换并解密共享包")
    redeem.add_argument("--package", required=True)
    redeem.add_argument("--code", required=True)
    redeem.add_argument("--out", required=True)
    redeem.add_argument("--server", required=True)
    redeem.add_argument(
        "--ca-file",
        help="只信任该 PEM 证书/CA（自签名部署用）；设置后不信任系统根证书",
    )
    redeem.add_argument("--sender-fingerprint", required=True,
                        help="发送方身份指纹（可信渠道取得 / TOFU）")
    redeem.add_argument("--broker-fingerprint", help="代理指纹（可选，但建议核对）")
    redeem.add_argument(
        "--container",
        help="本地加密容器 payload.vspk；本地交付的包必须提供，"
        "服务器交付的包提供后也不会重复下载",
    )
    redeem.set_defaults(func=cmd_redeem)

    admin = sub.add_parser("admin", help="管理命令")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    status = admin_sub.add_parser("status", help="查看状态摘要")
    status.set_defaults(func=cmd_admin_status)
    backup = admin_sub.add_parser("backup", help="备份状态与审计文件")
    backup.set_defaults(func=cmd_admin_backup)
    recover = admin_sub.add_parser("recover", help="人工恢复状态（需 --confirm）")
    recover.add_argument("--from-journal", action="store_true")
    recover.add_argument("--from-backup", action="store_true")
    recover.add_argument("--confirm", action="store_true")
    recover.set_defaults(func=cmd_admin_recover)
    passwd = admin_sub.add_parser("passwd", help="修改登录密码")
    passwd.add_argument("--old-password")
    passwd.add_argument("--new-password")
    passwd.set_defaults(func=cmd_admin_passwd)
    ack = admin_sub.add_parser("ack-init", help="删除一次性初始凭证文件")
    ack.set_defaults(func=cmd_admin_ack_init)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ApiError as exc:
        return _fail(f"{exc.message}（{exc.code}）")
    except (VaultShareError, ValueError) as exc:
        return _fail(str(getattr(exc, "message", exc)))
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
