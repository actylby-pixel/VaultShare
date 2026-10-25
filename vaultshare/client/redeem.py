"""接收方兑换与解包。

安全顺序（任一步失败都停止）：
1. 下载公开材料，独立验证发送方 KeyConfig / Policy 签名与身份绑定；
2. 若调用方给出发送方指纹（或容器要求核对），比对发送方身份指纹（TOFU），
   并核对代理指纹；未要求时只跳过这一项指纹比对，其余验证不变；
3. 生成临时 X25519 接收方密钥，HPKE 封装兑换请求；
4. 验证回执签名、``envelope_core`` 摘要与全部绑定字段；
5. 解封 ``K_pkg``，解密容器到临时目录，全部成功后才提交到输出目录。

密文来源有两种：服务器交付时下载 ``/blob``；本地交付时由发送方直接给出
``payload.vspk``（``local_payload``），服务器只提供元数据与口令。后者在提交
兑换前先校验容器头部、尺寸与摘要，避免白白消耗额度。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..crypto.keys import x25519_generate, x25519_public_bytes
from ..crypto.memsec import wipe
from ..errors import ValidationError
from ..protocol.container import read_container_meta, unpack_container
from ..protocol.envelope import open_envelope
from ..protocol.identity import verify_broker_identity, verify_sender_identity
from ..protocol.keyconfig import verify_keyconfig
from ..protocol.policy import policy_digest, verify_policy
from ..protocol.redeem import build_redeem_request
from ..util.canonical import sha256_hex
from ..util.pathcheck import ensure_within, validate_relpath
from .http import HttpClient

__all__ = ["RedeemResult", "redeem_package", "commit_staging"]


@dataclass(frozen=True)
class RedeemResult:
    package_id: str
    request_id: str
    output_dir: str
    manifest: dict
    broker_fingerprint: str
    sender_fingerprint: str


def _payload_mode(materials: dict) -> str:
    """交付方式；旧服务器没有该字段时按 ``server`` 处理。"""
    return str(materials.get("payload_mode") or "server")


def _verify_public(
    materials: dict,
    package_id: str,
    sender_fp: str | None,
    broker_fp: str | None,
):
    keyconfig = materials.get("keyconfig")
    policy = materials.get("policy")
    sender_record = materials.get("sender_identity")
    broker_record = materials.get("broker_identity")
    if not all(isinstance(x, dict) for x in (keyconfig, policy, sender_record, broker_record)):
        raise ValidationError("服务器返回的公开材料不完整")

    sender = verify_sender_identity(sender_record)
    # 只有发送方在容器里要求核对（或调用方主动给出指纹）时才做带外指纹比对。
    # 其余检查——身份记录自签名、KeyConfig/Policy 绑定、代理签名与回执——全部保留。
    if sender_fp is not None and sender.digest != sender_fp.lower():
        raise ValidationError("发送方身份指纹与预期不一致（可能被替换）")
    parsed_kc = verify_keyconfig(keyconfig, sender)
    parsed_policy = verify_policy(policy, sender)
    if parsed_kc.package_id != package_id or parsed_policy.package_id != package_id:
        raise ValidationError("公开材料的 package_id 不匹配")
    if keyconfig.get("policy_hash") != policy_digest(policy):
        raise ValidationError("KeyConfig 与 Policy 摘要不一致")

    broker = verify_broker_identity(broker_record)
    if broker.key_id != keyconfig["broker"]["key_id"]:
        raise ValidationError("代理身份与 KeyConfig 的 key_id 不一致")
    if broker.record["hpke_public_key"] != keyconfig["broker"]["hpke_public_key"]:
        raise ValidationError("代理 HPKE 公钥与 KeyConfig 不一致")
    if broker.record["signing_public_key"] != keyconfig["broker"]["signing_public_key"]:
        raise ValidationError("代理签名公钥与 KeyConfig 不一致")
    if broker.fingerprint != keyconfig["broker"]["fingerprint"]:
        raise ValidationError("代理指纹与 KeyConfig 不一致")
    if broker_fp is not None and broker.fingerprint != broker_fp.lower():
        raise ValidationError("代理指纹与可信指纹不一致")
    if materials.get("status") != "active":
        raise ValidationError("该包已撤销或不可兑换")
    # 本地交付的包在服务器上本来就没有密文，不能要求 payload 摘要；
    # 服务器交付的包必须已经上传过文件，否则元数据不完整。
    if _payload_mode(materials) == "server" and not materials.get("payload_sha256"):
        raise ValidationError("该包尚未上传文件")

    return parsed_kc, parsed_policy, broker, sender.digest


def _check_local_container(
    materials: dict, package_id: str, local_payload: str
) -> Path:
    """在提交兑换之前校验本地容器，避免校验失败还白白消耗一次额度。

    容器头部里的 ``package_id`` 必须与兑换包一致；服务器（仅服务器交付的包）
    声明的尺寸与 SHA-256 也要对得上。多 GB 文件只在这里哈希一次。
    """
    blob = Path(local_payload)
    if not blob.is_file():
        raise ValidationError(f"找不到本地加密容器：{local_payload}")
    with open(blob, "rb") as f:
        meta = read_container_meta(f)
    if meta.package_id != package_id:
        raise ValidationError("本地容器的 package_id 与兑换包不一致")
    expected_size = int(materials.get("payload_size") or 0)
    expected_sha = str(materials.get("payload_sha256") or "")
    if expected_size and blob.stat().st_size != expected_size:
        raise ValidationError("本地容器大小与服务器声明不一致")
    if expected_sha and _sha256(blob) != expected_sha:
        raise ValidationError("本地容器 SHA-256 与服务器声明不一致")
    return blob


def redeem_package(
    client: HttpClient,
    package_id: str,
    code: str,
    out_dir: str,
    *,
    sender_fingerprint: str | None,
    broker_fingerprint: str | None = None,
    local_payload: str | None = None,
) -> RedeemResult:
    materials = client.get(f"/api/v1/packages/{package_id}/public")
    parsed_kc, policy, broker, verified_sender_fp = _verify_public(
        materials, package_id, sender_fingerprint, broker_fingerprint
    )
    # 在提交兑换（会消耗一次额度）之前就把本地容器的问题挡下来。
    if local_payload is None and _payload_mode(materials) != "server":
        raise ValidationError(
            "该包为本地交付，服务器不保存密文；请选择发送方给你的容器"
        )
    local_blob = (
        _check_local_container(materials, package_id, local_payload)
        if local_payload
        else None
    )

    x_private, x_public = x25519_generate()
    outer, _inner = build_redeem_request(
        package_id=package_id,
        broker_hpke_public=parsed_kc.broker_hpke_public,
        code=code,
        recipient_public_key=x_public,
    )
    response = client.post("/api/v1/redeem", outer)
    envelope = response.get("envelope")
    if not isinstance(envelope, dict):
        raise ValidationError("服务器没有返回信封")
    core = envelope.get("envelope_core")
    receipt = envelope.get("receipt")
    if not isinstance(core, dict) or not isinstance(receipt, dict):
        raise ValidationError("信封结构非法")
    if core.get("package_id") != package_id or core.get("request_id") != outer["request_id"]:
        raise ValidationError("信封与本次请求不匹配")
    if core.get("recipient_pk_hash") != sha256_hex(x_public):
        raise ValidationError("信封接收方摘要不匹配")

    k_pkg = open_envelope(
        envelope,
        recipient_private_key=x_private,
        broker_signing_public=parsed_kc.broker_signing_public,
        package_id=package_id,
        grant_id=core.get("grant_id"),
        request_id=outer["request_id"],
        config_version=int(parsed_kc.record.get("version", 1)),
        broker_key_id=parsed_kc.broker_key_id,
    )
    try:
        return _unpack(
            client,
            package_id,
            out_dir,
            k_pkg,
            response,
            materials,
            broker.fingerprint,
            verified_sender_fp,
            local_blob,
        )
    finally:
        wipe(k_pkg)
        del x_private


def _unpack(
    client,
    package_id,
    out_dir,
    k_pkg,
    response,
    materials,
    broker_fp,
    sender_fp,
    local_blob=None,
):
    target = Path(out_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    target_existed = target.exists()
    if target_existed and any(target.iterdir()):
        raise ValidationError("输出目录必须为空")

    with tempfile.TemporaryDirectory(
        prefix=".vaultshare-redeem-", dir=str(target.parent)
    ) as work:
        expected_size = int(materials.get("payload_size") or 0)
        expected_sha = str(materials.get("payload_sha256") or "")
        if local_blob is not None:
            blob = Path(local_blob)
        else:
            if _payload_mode(materials) != "server":
                raise ValidationError(
                    "该包为本地交付，服务器不保存密文；请选择发送方给你的容器"
                )
            blob = Path(work) / "payload.vspk"
            written = client.download(
                f"/api/v1/packages/{package_id}/blob", str(blob)
            )
            if expected_size and written != expected_size:
                raise ValidationError("下载的容器大小与服务器声明不一致")
            if expected_sha and _sha256(blob) != expected_sha:
                raise ValidationError("下载的容器 SHA-256 与服务器声明不一致")

        staging = Path(work) / "stage"
        staging.mkdir()
        manifest = unpack_container(
            str(blob), str(staging), k_pkg, package_id
        )
        try:
            commit_staging(staging, target, manifest)
        except BaseException:
            if not target_existed:
                shutil.rmtree(target, ignore_errors=True)
            raise

    return RedeemResult(
        package_id=package_id,
        request_id=response.get("request_id", ""),
        output_dir=str(target),
        manifest=manifest,
        broker_fingerprint=broker_fp,
        sender_fingerprint=sender_fp,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def commit_staging(staging: str | Path, out_dir: str | Path, manifest: dict) -> None:
    """把已解密的 staging 提交到输出目录；不覆盖任何已有路径。"""
    staging_path = Path(staging)
    target = Path(out_dir)
    if target.exists() and any(target.iterdir()):
        raise ValidationError("输出目录必须为空")
    target.mkdir(parents=True, exist_ok=True)
    for entry in manifest.get("entries", []):
        rel = validate_relpath(entry["path"])
        src = staging_path.joinpath(*rel.parts)
        dst = target.joinpath(*rel.parts)
        ensure_within(target, dst)
        if entry["type"] == "dir":
            dst.mkdir(parents=True, exist_ok=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            raise ValidationError(f"目标已存在，拒绝覆盖：{dst}")
        os.replace(src, dst)
