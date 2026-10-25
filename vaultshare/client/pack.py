"""本地打包：单个文件或目录 → 加密容器 + 发送方签名的 KeyConfig / Policy。

强制步骤：**先核对代理身份指纹，再生成任何密钥**。调用方必须传入
``broker_identity``（带外核对的 JSON），这里会重新计算
``SHA256(canonical({key_id, hpke_public_key, signing_public_key}))`` 并与记录及
可选的 ``trusted_fingerprint`` 比对。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ..crypto.memsec import wipe
from ..crypto.stream import decrypt_chunks
from ..errors import ValidationError
from ..protocol.container import (
    MAX_MANIFEST_BYTES,
    make_aad,
    pack_directory,
    read_container_header,
)
from ..protocol.identity import BrokerIdentity, SenderIdentity, verify_broker_identity
from ..protocol.keyconfig import build_keyconfig
from ..protocol.policy import build_policy, policy_digest
from ..protocol.upload_key import build_upload_key
from ..util.canonical import canonical_bytes, sha256_hex
from ..util.ids import PKG_ID_BYTES, is_hex_id, new_hex_id
from ..util.serverurl import normalize_server_url
from ..util.timeutil import now, parse_duration
from .identity import SenderKeys

__all__ = [
    "PackInfo",
    "EncryptedPackageInfo",
    "pack_package",
    "encrypt_package",
    "load_broker_identity",
    "verify_container",
    "prepare_output_dir",
    "UPLOAD_KEY_FILENAME",
    "PAYLOAD_FILENAME",
    "PACKAGE_FILENAME",
]

PACKAGE_FORMAT = "vaultshare-package-bundle"
UPLOAD_KEY_FILENAME = "upload-key.json"
PAYLOAD_FILENAME = "payload.vspk"
PACKAGE_FILENAME = "package.json"


def prepare_output_dir(out_dir: str, names: tuple[str, ...]) -> Path:
    """输出目录可以已存在、也可以有别的文件；只拒绝会覆盖已有产物的冲突。"""
    target = Path(out_dir)
    if target.exists() and not target.is_dir():
        raise ValidationError("输出路径已存在，但不是目录")
    if target.is_dir():
        conflicts = [name for name in names if (target / name).exists()]
        if conflicts:
            raise ValidationError(
                "输出目录中已存在 "
                + "、".join(conflicts)
                + "，请换一个目录或先移走这些文件"
            )
    return target


@dataclass(frozen=True)
class PackInfo:
    package_id: str
    out_dir: str
    policy_hash: str
    keyconfig_sha256: str
    policy_sha256: str
    payload_sha256: str
    payload_size: int
    manifest_files: int
    manifest_bytes: int


@dataclass(frozen=True)
class EncryptedPackageInfo:
    package_id: str
    out_dir: str
    server_url: str
    payload_sha256: str
    payload_size: int
    manifest_files: int
    manifest_bytes: int
    sender_fingerprint: str
    upload_key_path: str


def encrypt_package(
    src: str,
    out_dir: str,
    keys: SenderKeys,
    *,
    server_url: str,
    package_id: str | None = None,
    require_sender_fingerprint: bool = True,
    progress=None,
) -> EncryptedPackageInfo:
    """只加密：生成容器与上传凭据，不生成 KeyConfig/Policy，也不联网。

    ``K_pkg`` 会用发送方身份中的 X25519 公钥密封到 ``upload-key.json``；上传
    步骤再决定口令数量/次数/有效期并生成签名策略。``server_url`` 必须提供：
    它会写进容器头部（AAD 覆盖），供接收方自动填入。
    """
    if not (os.path.isfile(src) or os.path.isdir(src)):
        raise ValidationError("源路径必须是文件或目录")
    server_url = normalize_server_url(server_url)
    if not server_url:
        raise ValidationError("请填写要写入容器的服务器地址")
    package_id = package_id or new_hex_id(PKG_ID_BYTES)
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")

    target = prepare_output_dir(
        out_dir, (PAYLOAD_FILENAME, UPLOAD_KEY_FILENAME, PACKAGE_FILENAME)
    )
    target.mkdir(parents=True, exist_ok=True)

    created = now()
    k_pkg = bytearray(os.urandom(32))
    try:
        payload_path = target / PAYLOAD_FILENAME
        result = pack_directory(
            src,
            payload_path,
            k_pkg,
            package_id,
            server_url=server_url,
            require_sender_fingerprint=require_sender_fingerprint,
            progress=progress,
        )
        plaintext = verify_container(str(payload_path), k_pkg, package_id)
        # 注意：这里不能再用 sha256_hex()，那会把摘要字节再哈希一次。
        payload_sha = _file_digest(payload_path).hex()
        payload_size = payload_path.stat().st_size
        upload_key = build_upload_key(
            package_id=package_id,
            server=server_url,
            payload_sha256=payload_sha,
            sender=keys.identity,
            signer_private=keys.ed25519_private,
            k_pkg=k_pkg,
            created_at=created,
        )
    finally:
        wipe(k_pkg)

    bundle = {
        "format": PACKAGE_FORMAT,
        "version": 1,
        "stage": "encrypted",
        "package_id": package_id,
        "server": server_url,
        "payload_sha256": payload_sha,
        "payload_size": payload_size,
        "manifest_sha256": result.manifest_sha256,
        "manifest_files": result.manifest["total_files"],
        "manifest_bytes": result.manifest["total_bytes"],
        "verified_plaintext_bytes": plaintext,
        "sender_identity_hash": keys.identity.digest,
        "require_sender_fingerprint": bool(require_sender_fingerprint),
        "created_at": created,
    }
    upload_key_path = target / UPLOAD_KEY_FILENAME
    (target / PACKAGE_FILENAME).write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    upload_key_path.write_bytes(canonical_bytes(upload_key) + b"\n")
    return EncryptedPackageInfo(
        package_id=package_id,
        out_dir=str(target),
        server_url=server_url,
        payload_sha256=payload_sha,
        payload_size=payload_size,
        manifest_files=result.manifest["total_files"],
        manifest_bytes=result.manifest["total_bytes"],
        sender_fingerprint=keys.identity.digest,
        upload_key_path=str(upload_key_path),
    )


def load_broker_identity(path: str, trusted_fingerprint: str | None = None) -> BrokerIdentity:
    try:
        with open(path, "rb") as f:
            record = json.loads(f.read().decode("utf-8"))
    except OSError as exc:
        raise ValidationError(f"无法读取代理身份文件：{exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("代理身份文件不是合法 JSON") from exc
    identity = verify_broker_identity(record, expected_fingerprint=trusted_fingerprint)
    return identity


def verify_container(path: str, k_pkg: bytes, package_id: str) -> int:
    """用 ``K_pkg`` 完整解密一遍，验证所有 chunk 的认证标签。返回明文字节数。"""
    from ..crypto.kdf import stream_key

    key = stream_key(k_pkg, bytes.fromhex(package_id))
    total = 0
    first = True
    try:
        with open(path, "rb") as src:
            header = read_container_header(src, package_id)
            for message in decrypt_chunks(src, key, header, make_aad):
                if first:
                    first = False
                    if len(message) < 4:
                        raise ValidationError("容器首条消息不含 manifest 长度")
                    length = int.from_bytes(message[:4], "big")
                    if length <= 0 or length > MAX_MANIFEST_BYTES:
                        raise ValidationError("容器 manifest 长度非法")
                    if len(message) < 4 + length:
                        raise ValidationError("容器 manifest 被截断")
                    try:
                        manifest = json.loads(message[4 : 4 + length].decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise ValidationError("容器 manifest 不是合法 JSON") from exc
                    if manifest.get("package_id") != package_id:
                        raise ValidationError("容器 manifest 的 package_id 不匹配")
                total += len(message)
        if first:
            raise ValidationError("容器为空")
    finally:
        wipe(key)
    return total


def pack_package(
    src: str,
    out_dir: str,
    keys: SenderKeys,
    broker: BrokerIdentity,
    *,
    codes: int,
    max_uses: int,
    expires: str = "7d",
    package_id: str | None = None,
    server_url: str = "",
    require_sender_fingerprint: bool = True,
    progress=None,
) -> PackInfo:
    if not (os.path.isfile(src) or os.path.isdir(src)):
        raise ValidationError("源路径必须是文件或目录")
    server_url = normalize_server_url(server_url)
    if codes < 1 or codes > 10_000:
        raise ValidationError("codes 必须在 1..10000 之间")
    if max_uses < 1 or max_uses > 1_000_000:
        raise ValidationError("max_uses 必须在 1..1000000 之间")
    try:
        expires_seconds = parse_duration(expires)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    package_id = package_id or new_hex_id(PKG_ID_BYTES)
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")

    target = prepare_output_dir(
        out_dir,
        (
            PAYLOAD_FILENAME,
            UPLOAD_KEY_FILENAME,
            PACKAGE_FILENAME,
            "keyconfig.json",
            "policy.json",
        ),
    )
    target.mkdir(parents=True, exist_ok=True)

    created = now()
    latest_expiry = created + expires_seconds
    identity: SenderIdentity = keys.identity
    ed_private = keys.ed25519_private

    policy = build_policy(
        package_id,
        identity,
        ed_private,
        max_codes=codes,
        max_uses_per_code=max_uses,
        max_total_redemptions=codes * max_uses,
        latest_expiry=latest_expiry,
        created_at=created,
    )
    policy_hash = policy_digest(policy)
    k_pkg = bytearray(os.urandom(32))
    try:
        keyconfig = build_keyconfig(
            package_id,
            policy_hash,
            k_pkg,
            broker,
            identity,
            ed_private,
            created_at=created,
        )
        payload_path = target / PAYLOAD_FILENAME
        result = pack_directory(
            src,
            payload_path,
            k_pkg,
            package_id,
            server_url=server_url,
            require_sender_fingerprint=require_sender_fingerprint,
            progress=progress,
        )
        plaintext = verify_container(str(payload_path), k_pkg, package_id)
    finally:
        wipe(k_pkg)

    keyconfig_bytes = canonical_bytes(keyconfig)
    policy_bytes = canonical_bytes(policy)
    payload_sha = _file_digest(payload_path).hex()
    payload_size = payload_path.stat().st_size
    kc_path = target / "keyconfig.json"
    policy_path = target / "policy.json"
    kc_path.write_bytes(keyconfig_bytes)
    policy_path.write_bytes(policy_bytes)
    bundle = {
        "format": PACKAGE_FORMAT,
        "version": 1,
        "package_id": package_id,
        "server": server_url,
        "codes": codes,
        "max_uses": max_uses,
        "expires_at": latest_expiry,
        "policy_hash": policy_hash,
        "keyconfig_sha256": sha256_hex(keyconfig_bytes),
        "policy_sha256": sha256_hex(policy_bytes),
        "payload_sha256": payload_sha,
        "payload_size": payload_size,
        "manifest_sha256": result.manifest_sha256,
        "manifest_files": result.manifest["total_files"],
        "manifest_bytes": result.manifest["total_bytes"],
        "verified_plaintext_bytes": plaintext,
        "require_sender_fingerprint": bool(require_sender_fingerprint),
    }
    (target / PACKAGE_FILENAME).write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return PackInfo(
        package_id=package_id,
        out_dir=str(target),
        policy_hash=policy_hash,
        keyconfig_sha256=bundle["keyconfig_sha256"],
        policy_sha256=bundle["policy_sha256"],
        payload_sha256=payload_sha,
        payload_size=payload_size,
        manifest_files=result.manifest["total_files"],
        manifest_bytes=result.manifest["total_bytes"],
    )


def _file_digest(path: Path) -> bytes:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()
