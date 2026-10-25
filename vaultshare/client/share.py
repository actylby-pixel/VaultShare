"""上传打包目录并领取口令（CLI 与 GUI 共用）。

流程：注册身份 → 创建包元数据 →（可选）上传密文 → 代理发码 →
用发送方私钥解封口令。服务器与日志都不会看到明文口令。

两种交付方式：
* ``payload_mode="server"``：密文上传到服务器，接收方凭口令下载（默认）；
* ``payload_mode="local"``：服务器只保存元数据、策略与口令，**不接收密文**；
  发送方直接把 ``payload.vspk`` 交给接收方，接收方本地解密。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from ..crypto.memsec import wipe
from ..errors import ValidationError, VaultShareError
from ..protocol.identity import BrokerIdentity
from ..protocol.keyconfig import build_keyconfig
from ..protocol.policy import build_policy, policy_digest, verify_policy
from ..protocol.upload_key import open_upload_key, verify_upload_key
from ..util.canonical import canonical_bytes, sha256_hex
from ..util.serverurl import normalize_server_url
from ..util.timeutil import now, parse_duration
from .codes import open_sealed_code
from .http import ApiError, HttpClient
from .identity import SenderKeys
from .pack import UPLOAD_KEY_FILENAME, verify_container

__all__ = [
    "UploadedCode",
    "UploadResult",
    "upload_package",
    "read_package_bundle",
    "sha256_file",
    "batch_id_for",
    "is_deferred_package",
    "ensure_share_ready",
]


@dataclass(frozen=True)
class UploadedCode:
    grant_id: str
    code: str
    formatted: str
    used: int
    max_uses: int
    expires_at: int


@dataclass(frozen=True)
class UploadResult:
    package_id: str
    batch_id: str
    codes: list[UploadedCode]
    created: bool
    broker_fingerprint: str = ""
    server: str = ""


def batch_id_for(package_id: str) -> str:
    return sha256_hex(b"vaultshare/batch/" + package_id.encode("ascii"))[:32]


def sha256_file(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_deferred_package(directory: str | os.PathLike) -> bool:
    """只加密的包：有上传凭据，但还没有 KeyConfig/Policy。"""
    base = Path(directory)
    return (base / UPLOAD_KEY_FILENAME).is_file() and not (base / "keyconfig.json").is_file()


def _normalized_bundle_server(bundle: dict) -> str:
    try:
        return normalize_server_url(str(bundle.get("server") or ""))
    except ValidationError as exc:
        raise ValidationError(f"package.json 的服务器地址非法：{exc.message}") from exc


def ensure_share_ready(
    directory: str | os.PathLike,
    keys: SenderKeys,
    broker: BrokerIdentity | None,
    *,
    codes: int,
    max_uses: int,
    expires: str,
    expected_server: str | None = None,
    verify_payload: bool = True,
    max_codes: int | None = None,
) -> dict:
    """为“只加密”的包按现在的选择生成 Policy/KeyConfig。

    已生成过则直接复用；这使上传失败后的重试不会改变已签名的策略。返回更新后的
    ``package.json`` 内容，字段集合与 ``pack_package`` 的完整包一致。

    ``verify_payload=False`` 只用于“本地交付”的网页上传：容器不经过服务器，
    服务器无法验证它，因此跳过“用 K_pkg 解密一遍”的检查。上传凭据的签名、
    身份绑定与摘要仍然验证；发送方自己的加密流程已经完整验证过容器。

    ``max_codes`` 是策略允许的**口令总数上限**（含以后新增），默认等于本次
    的 ``codes``。网页上传用它预留额度：本次只生成 ``codes`` 个，之后还能在
    上限内继续增加。策略一旦签名就无法放宽，所以必须在这里给足。
    """
    limit = int(codes) if max_codes is None else int(max_codes)
    if limit < int(codes):
        raise ValidationError("口令总数上限不能小于本次生成数量")
    base = Path(directory)
    try:
        bundle = json.loads((base / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"无法读取 package.json：{exc}") from exc
    payload = base / "payload.vspk"
    if verify_payload and not payload.is_file():
        raise ValidationError("打包目录缺少 payload.vspk")
    package_id = str(bundle.get("package_id") or "")
    if expected_server is not None:
        wanted = normalize_server_url(expected_server)
        if wanted and wanted != _normalized_bundle_server(bundle):
            raise ValidationError("服务器地址与加密时写入容器/上传凭据的地址不一致")

    if (base / "keyconfig.json").is_file() or (base / "policy.json").is_file():
        if not ((base / "keyconfig.json").is_file() and (base / "policy.json").is_file()):
            raise ValidationError("包内 KeyConfig 与 Policy 不完整，无法继续上传")
        policy = json.loads((base / "policy.json").read_text(encoding="utf-8"))
        parsed = verify_policy(policy, identity=keys.identity)
        if parsed.package_id != package_id:
            raise ValidationError("Policy 的 package_id 与包不一致")
        keyconfig = json.loads((base / "keyconfig.json").read_text(encoding="utf-8"))
        if keyconfig.get("policy_hash") != parsed.policy_hash:
            raise ValidationError("KeyConfig 与 Policy 摘要不一致")
        # 崩溃恢复：KeyConfig/Policy 已落盘但 package.json 尚未补齐时，用
        # 已签名的策略回填上传参数。
        changed = False
        recovered = {
            "codes": parsed.max_codes,
            "max_uses": parsed.max_uses_per_code,
            "expires_at": parsed.latest_expiry,
            "policy_hash": parsed.policy_hash,
            "stage": "share-ready",
        }
        for key, value in recovered.items():
            if bundle.get(key) != value:
                bundle[key] = value
                changed = True
        if changed:
            _write_bundle(base, bundle)
        return bundle

    if not (base / UPLOAD_KEY_FILENAME).is_file():
        raise ValidationError("这里不是可上传的 VaultShare 包（缺少上传凭据）")
    if broker is None:
        raise ValidationError("生成分享策略需要已核对的代理身份")
    if codes < 1 or codes > 10_000:
        raise ValidationError("codes 必须在 1..10000 之间")
    if limit > 10_000:
        raise ValidationError("口令总数上限不能超过 10000")
    if max_uses < 1 or max_uses > 1_000_000:
        raise ValidationError("max_uses 必须在 1..1000000 之间")
    try:
        expires_seconds = parse_duration(expires)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    try:
        upload_record = json.loads(
            (base / UPLOAD_KEY_FILENAME).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"无法读取上传凭据：{exc}") from exc
    parsed_upload = verify_upload_key(upload_record, identity=keys.identity)
    if parsed_upload.package_id != package_id:
        raise ValidationError("上传凭据的 package_id 与包不一致")
    if parsed_upload.payload_sha256 != str(bundle.get("payload_sha256") or ""):
        raise ValidationError("上传凭据的容器摘要与 package.json 不一致")
    if parsed_upload.server != _normalized_bundle_server(bundle):
        raise ValidationError("上传凭据的服务器地址与 package.json 不一致")

    created = now()
    k_pkg = open_upload_key(
        parsed_upload, keys.x25519_private, keys.x25519_public
    )
    try:
        # 用解出的 K_pkg 完整验证一遍容器，确保上传凭据确实对应这个密文。
        if verify_payload:
            verify_container(str(payload), k_pkg, package_id)
        policy = build_policy(
            package_id,
            keys.identity,
            keys.ed25519_private,
            max_codes=limit,
            max_uses_per_code=int(max_uses),
            max_total_redemptions=limit * int(max_uses),
            latest_expiry=created + expires_seconds,
            created_at=created,
        )
        policy_hash = policy_digest(policy)
        keyconfig = build_keyconfig(
            package_id,
            policy_hash,
            k_pkg,
            broker,
            keys.identity,
            keys.ed25519_private,
            created_at=created,
        )
    finally:
        wipe(k_pkg)

    keyconfig_bytes = canonical_bytes(keyconfig)
    policy_bytes = canonical_bytes(policy)
    (base / "keyconfig.json").write_bytes(keyconfig_bytes)
    (base / "policy.json").write_bytes(policy_bytes)
    bundle.update(
        {
            "stage": "share-ready",
            "codes": int(codes),
            "max_uses": int(max_uses),
            "expires_at": created + expires_seconds,
            "policy_hash": policy_hash,
            "keyconfig_sha256": sha256_hex(keyconfig_bytes),
            "policy_sha256": sha256_hex(policy_bytes),
            "share_created_at": created,
        }
    )
    _write_bundle(base, bundle)
    return bundle


def _write_bundle(base: Path, bundle: dict) -> None:
    (base / "package.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def read_package_bundle(directory: str | os.PathLike) -> tuple[dict, dict, dict, Path]:
    base = Path(directory)
    try:
        bundle = json.loads((base / "package.json").read_text(encoding="utf-8"))
        keyconfig = json.loads((base / "keyconfig.json").read_text(encoding="utf-8"))
        policy = json.loads((base / "policy.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultShareError(f"无法读取打包目录：{exc}") from exc
    payload = base / "payload.vspk"
    if not payload.is_file():
        raise VaultShareError("打包目录缺少 payload.vspk")
    return bundle, keyconfig, policy, payload


def upload_package(
    client: HttpClient,
    package_dir: str | os.PathLike,
    keys: SenderKeys,
    *,
    payload_mode: str = "server",
) -> UploadResult:
    """幂等上传；同一目录重复执行不会重复计数或重复发码。

    ``payload_mode="local"`` 时只创建元数据与口令，不上传 ``payload.vspk``。
    """
    if payload_mode not in ("server", "local"):
        raise ValidationError("payload_mode 只能是 server 或 local")
    bundle, keyconfig, policy, payload_path = read_package_bundle(package_dir)
    package_id = str(bundle.get("package_id") or "")
    if not package_id:
        raise VaultShareError("package.json 缺少 package_id")

    client.post("/api/v1/identity", keys.identity.record)
    created = False
    try:
        client.post(
            "/api/v1/packages",
            {"keyconfig": keyconfig, "policy": policy, "payload_mode": payload_mode},
        )
        created = True
    except ApiError as exc:
        if exc.code != "package_exists":
            raise

    public = client.get(f"/api/v1/packages/{package_id}/public")
    existing_mode = str(public.get("payload_mode") or "server")
    if existing_mode != payload_mode:
        raise VaultShareError(
            "该 package_id 已按另一种交付方式创建（"
            f"服务器上为 {existing_mode}），请使用相同方式或换一个包。"
        )
    if payload_mode == "server":
        local_sha = sha256_file(payload_path)
        local_size = os.path.getsize(payload_path)
        if public.get("payload_sha256"):
            if public["payload_sha256"] != local_sha:
                raise VaultShareError("服务器上已有不同的 payload 摘要，拒绝覆盖")
        else:
            client.put_file(
                f"/api/v1/packages/{package_id}/blob",
                str(payload_path),
                local_sha,
                local_size,
            )

    batch_id = batch_id_for(package_id)
    try:
        client.post(
            f"/api/v1/packages/{package_id}/grants",
            {
                "count": int(bundle["codes"]),
                "uses_per_code": int(bundle["max_uses"]),
                "expires_at": int(bundle["expires_at"]),
                "batch_id": batch_id,
            },
        )
    except ApiError as exc:
        if exc.code in ("quota_denied", "conflict"):
            raise VaultShareError(f"口令创建未完成：{exc.message}") from exc
        raise

    response = client.get(f"/api/v1/packages/{package_id}/codes")
    codes: list[UploadedCode] = []
    for grant in response.get("grants") or []:
        sealed = open_sealed_code(
            package_id,
            grant["grant_id"],
            grant.get("sealed_code") or {},
            keys.x25519_private,
            keys.identity.x25519_public,
        )
        codes.append(
            UploadedCode(
                grant_id=str(grant["grant_id"]),
                code=sealed.code,
                formatted=sealed.formatted,
                used=int(grant.get("used", 0)),
                max_uses=int(grant.get("max_uses", 0)),
                expires_at=int(grant.get("expires_at", 0)),
            )
        )
    if not codes:
        raise ValidationError("服务器没有返回口令")
    broker = keyconfig.get("broker") or {}
    return UploadResult(
        package_id=package_id,
        batch_id=batch_id,
        codes=codes,
        created=created,
        broker_fingerprint=str(broker.get("fingerprint") or ""),
        server=str(bundle.get("server") or ""),
    )
