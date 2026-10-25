"""服务器侧的共享包一致性检查。

服务器**不信任**磁盘上的 KeyConfig/Policy：每次都按状态文件里记录的 SHA-256
读取，再验证发送方签名、发送方身份字段、策略摘要与代理指纹。文件被替换、
签名被去掉、身份被换绑，都会在这里失败。
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..config import Settings
from ..errors import Conflict, NotFound, ValidationError
from ..protocol.identity import check_sender_fields
from ..protocol.keyconfig import KeyConfigParsed, verify_keyconfig
from ..protocol.policy import SharePolicy, policy_digest, verify_policy
from ..storage.package_store import read_keyconfig_bytes, read_policy_bytes, payload_path
from ..util.canonical import sha256_hex

__all__ = ["PackageContext", "load_package_context"]


@dataclass(frozen=True)
class PackageContext:
    package_id: str
    package: dict
    keyconfig: dict
    policy: dict
    keyconfig_parsed: KeyConfigParsed
    policy_parsed: SharePolicy
    sender_entry: dict
    keyconfig_bytes: bytes
    policy_bytes: bytes


def load_package_context(
    settings: Settings,
    body: dict,
    package_id: str,
    *,
    require_active: bool = True,
    require_payload: bool = False,
) -> PackageContext:
    package = body.get("packages", {}).get(package_id)
    if not isinstance(package, dict):
        raise NotFound("package 不存在")
    if require_active and package.get("status") != "active":
        raise ValidationError("package 已停用或撤销", code="package_inactive")
    if package_id in body.get("revoked_packages", {}):
        raise ValidationError("package 已撤销", code="package_revoked")
    sender_key_id = package.get("sender_key_id")
    entry = body.get("senders", {}).get(sender_key_id)
    if not isinstance(entry, dict):
        raise ValidationError("发送方身份未注册", code="sender_unknown")
    if entry.get("revoked"):
        raise ValidationError("发送方身份已撤销", code="sender_revoked")

    try:
        kc_bytes = read_keyconfig_bytes(settings, package_id)
        policy_bytes = read_policy_bytes(settings, package_id)
    except NotFound as exc:
        raise Conflict("package 文件缺失", code="package_corrupt") from exc
    if sha256_hex(kc_bytes) != package.get("keyconfig_sha256"):
        raise Conflict("KeyConfig 摘要与状态不一致", code="package_corrupt")
    if sha256_hex(policy_bytes) != package.get("policy_sha256"):
        raise Conflict("Policy 摘要与状态不一致", code="package_corrupt")

    try:
        keyconfig = json.loads(kc_bytes.decode("utf-8"))
        policy = json.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Conflict("package 元数据损坏", code="package_corrupt") from exc

    parsed_kc = verify_keyconfig(keyconfig)
    parsed_policy = verify_policy(policy)
    if parsed_kc.package_id != package_id or parsed_policy.package_id != package_id:
        raise Conflict("package_id 不一致", code="package_corrupt")
    if keyconfig.get("sender_key_id") != sender_key_id:
        raise Conflict("KeyConfig 发送方与状态不一致", code="package_corrupt")
    check_sender_fields(keyconfig, entry, "KeyConfig")
    check_sender_fields(policy, entry, "Policy")
    if keyconfig.get("sender_identity_hash") != package.get("sender_identity_hash"):
        raise Conflict("KeyConfig 身份摘要与状态不一致", code="package_corrupt")
    if policy.get("sender_identity_hash") != package.get("sender_identity_hash"):
        raise Conflict("Policy 身份摘要与状态不一致", code="package_corrupt")
    if keyconfig.get("policy_hash") != policy_digest(policy):
        raise Conflict("KeyConfig 的 policy_hash 与 Policy 不一致", code="package_corrupt")
    if keyconfig.get("broker", {}).get("key_id") != package.get("broker_key_id"):
        raise Conflict("KeyConfig 代理 key_id 与状态不一致", code="package_corrupt")

    # ``payload_mode=local`` 的包由发送方直接交付容器，服务器不保存密文，
    # 因此不受“文件必须先上传”的约束；其余包保持原有要求。
    if require_payload and package.get("payload_mode", "server") != "local":
        if not package.get("payload_sha256"):
            raise ValidationError("共享包文件尚未上传", code="payload_missing")
        if not payload_path(settings, package_id).is_file():
            raise Conflict("共享包文件缺失", code="payload_missing")

    return PackageContext(
        package_id=package_id,
        package=package,
        keyconfig=keyconfig,
        policy=policy,
        keyconfig_parsed=parsed_kc,
        policy_parsed=parsed_policy,
        sender_entry=entry,
        keyconfig_bytes=kc_bytes,
        policy_bytes=policy_bytes,
    )
