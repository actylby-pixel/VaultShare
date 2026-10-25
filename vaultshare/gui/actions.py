"""GUI 背后的业务动作（不依赖 Qt，便于单独测试）。

加密工具只做本地加密：生成 ``payload.vspk`` 与 ``upload-key.json``，不联网、
不生成口令策略。解密工具只做兑换与解密。所有网络、KDF、加解密都在工作线程里
调用这里的函数。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..client.http import HttpClient
from ..client.identity import SenderKeys, create_identity, load_identity
from ..client.pack import (
    PACKAGE_FILENAME,
    PAYLOAD_FILENAME,
    UPLOAD_KEY_FILENAME,
    encrypt_package,
    prepare_output_dir,
)
from ..client.redeem import RedeemResult, redeem_package
from ..errors import ValidationError
from ..protocol.container import read_container_meta
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..util.serverurl import normalize_server_url

__all__ = [
    "EncryptInput",
    "EncryptOutput",
    "DecryptInput",
    "run_encrypt",
    "run_decrypt",
    "load_source_hint",
    "SourceHint",
]


@dataclass
class EncryptInput:
    server: str
    source: str
    output: str
    identity_prefix: str
    identity_password: str
    # 发送方是否要求接收方在兑换前核对发送方身份指纹。
    require_sender_fingerprint: bool = True


@dataclass
class EncryptOutput:
    package_id: str
    server: str
    sender_fingerprint: str
    container_path: str
    upload_key_path: str
    output_dir: str
    identity_public_path: str
    identity_key_path: str
    manifest_files: int
    manifest_bytes: int
    payload_size: int
    require_sender_fingerprint: bool = True


@dataclass
class DecryptInput:
    # 容器路径是权威来源；server/package_id 仅供不使用容器的调用方回退。
    server: str
    package_id: str
    code: str
    output: str
    sender_fingerprint: str = ""
    broker_fingerprint: str = ""
    container: str = ""


@dataclass
class SourceHint:
    server: str
    package_id: str
    sender_fingerprint: str = ""
    broker_fingerprint: str = ""
    code: str | None = None
    kind: str = "card"
    require_sender_fingerprint: bool = True


def _load_or_create_identity(prefix: str, password: str) -> SenderKeys:
    if not password:
        raise ValidationError("请填写身份私钥口令")
    public_path = Path(f"{prefix}.json")
    key_path = Path(f"{prefix}.key")
    if public_path.exists() != key_path.exists():
        raise ValidationError("身份文件不完整：.json 与 .key 必须成对存在")
    if not public_path.exists():
        return create_identity(prefix, password=password)
    return load_identity(prefix, password=password)


def run_encrypt(data: EncryptInput, status=lambda _msg: None) -> EncryptOutput:
    server = normalize_server_url(data.server)
    if not server:
        raise ValidationError("请填写要写入容器的服务器地址")
    source = Path(data.source)
    if not (source.is_file() or source.is_dir()):
        raise ValidationError("请选择要加密的文件或文件夹")
    if not (data.output or "").strip():
        raise ValidationError("请选择输出目录")
    output = prepare_output_dir(
        data.output, (PAYLOAD_FILENAME, UPLOAD_KEY_FILENAME, PACKAGE_FILENAME)
    )

    status("读取或创建发送方身份…")
    keys = _load_or_create_identity(data.identity_prefix, data.identity_password)

    status("加密（大文件需要一些时间）…")
    info = encrypt_package(
        str(source),
        str(output),
        keys,
        server_url=server,
        require_sender_fingerprint=bool(data.require_sender_fingerprint),
        progress=lambda n: status(f"已加密 {n // (1024 * 1024)} MiB…"),
    )
    status("完成")
    return EncryptOutput(
        package_id=info.package_id,
        server=info.server_url,
        sender_fingerprint=keys.identity.digest,
        container_path=str(Path(info.out_dir) / PAYLOAD_FILENAME),
        upload_key_path=info.upload_key_path,
        output_dir=info.out_dir,
        identity_public_path=str(Path(f"{data.identity_prefix}.json").resolve()),
        identity_key_path=str(Path(f"{data.identity_prefix}.key").resolve()),
        manifest_files=info.manifest_files,
        manifest_bytes=info.manifest_bytes,
        payload_size=info.payload_size,
        require_sender_fingerprint=bool(data.require_sender_fingerprint),
    )


def run_decrypt(data: DecryptInput, status=lambda _msg: None) -> RedeemResult:
    server = ""
    package_id = ""
    require_fp = True
    container = (data.container or "").strip()
    if container:
        # 容器是权威来源：服务器地址、package_id 与是否要求核对指纹都来自头部。
        try:
            with open(container, "rb") as f:
                meta = read_container_meta(f)
        except OSError as exc:
            raise ValidationError(f"无法打开加密容器：{exc}") from exc
        server = normalize_server_url(meta.server_url)
        if not server:
            # 旧版容器没有地址：允许调用方（界面上的补填框）提供。
            server = normalize_server_url(data.server)
        if not server:
            raise ValidationError(
                "这个容器里没有服务器地址（旧版容器），请填写服务器地址。"
            )
        package_id = meta.package_id
        require_fp = meta.require_sender_fingerprint
    else:
        server = normalize_server_url(data.server)
        if not server:
            raise ValidationError("请选择加密容器（其中包含服务器地址）")
        package_id = (data.package_id or "").strip().lower()
        if not is_hex_id(package_id, PKG_ID_BYTES):
            raise ValidationError("package_id 格式非法")

    fp = (data.sender_fingerprint or "").strip().lower()
    if fp:
        if len(fp) != 64 or any(ch not in "0123456789abcdef" for ch in fp):
            raise ValidationError("发送方指纹格式非法（64 位十六进制）")
    elif require_fp:
        raise ValidationError("发送方要求核对身份指纹，请填写发送方指纹（64 位十六进制）")

    broker_fp = (data.broker_fingerprint or "").strip().lower() or None
    if broker_fp is not None and (
        len(broker_fp) != 64 or any(ch not in "0123456789abcdef" for ch in broker_fp)
    ):
        raise ValidationError("代理指纹格式非法")
    if not data.code.strip():
        raise ValidationError("请填写兑换口令")
    if not data.output.strip():
        raise ValidationError("请选择解密输出目录")

    status("向服务器申请密钥并解密…")
    client = HttpClient(server)
    return redeem_package(
        client,
        package_id,
        data.code,
        data.output,
        sender_fingerprint=fp or None,
        broker_fingerprint=broker_fp,
        local_payload=container or None,
    )


def load_source_hint(path: str) -> SourceHint:
    """打开分享卡片或加密容器，提取可自动填充的公开信息。"""
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix == ".vspk":
        try:
            with open(target, "rb") as f:
                meta = read_container_meta(f)
        except Exception as exc:  # noqa: BLE001 - UI 统一显示
            raise ValidationError(f"无法读取容器头部：{exc}") from exc
        return SourceHint(
            server=meta.server_url,
            package_id=meta.package_id,
            kind="container",
            require_sender_fingerprint=meta.require_sender_fingerprint,
        )
    if suffix in (".json", ".vsshare"):
        from ..client.share_card import load_card

        card = load_card(target)
        return SourceHint(
            server=card.server,
            package_id=card.package_id,
            sender_fingerprint=card.sender_fingerprint,
            broker_fingerprint=card.broker_fingerprint,
            code=card.code,
            kind="card",
        )
    raise ValidationError("请选择分享卡片（.json）或加密容器（.vspk）")
