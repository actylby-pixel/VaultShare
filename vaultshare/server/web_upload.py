"""服务器网页上传：把“只加密”的包在服务器端变成可兑换的共享包。

**这会改变信任边界**：网页上传需要发送方私钥和口令才能解开 ``K_pkg``，因此
Web 进程会短暂接触私钥与 ``K_pkg`` 明文。该功能默认关闭，只有显式设置
``VAULTSHARE_WEB_UPLOAD=1`` 才会启用；风险见 ``docs/SECURITY.md``。

流程复用现有组件，不另写协议：

1. 校验上传文件，还原出 ``upload-key.json`` / ``package.json`` / 发送方身份
   （``payload.vspk`` 只在服务器交付时需要）；
2. ``ensure_share_ready`` 验签、核对摘要、解封 ``K_pkg``，并按本次选择生成
   KeyConfig / Policy；服务器交付时还会完整验证容器；
3. 通过服务器自己的 Bearer API 注册身份、创建包、上传密文（仅服务器交付）、
   创建口令；
4. 用发送方私钥解开服务端返回的密封口令，交给页面显示。

若选择“本地交付”，服务器不接收密文：``payload.vspk`` 既不保存也不上传，
只保存元数据与口令，由发送方自己把容器交给接收方。注意浏览器仍会把所选文件
发到 Web 进程，所以本地交付时**不要选择** ``payload.vspk``。

Web 进程不会把口令、私钥或 ``K_pkg`` 写进日志；临时文件在请求结束时删除。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from flask import current_app

from ..client.codes import open_sealed_code
from ..client.identity import SenderKeys, load_identity
from ..client.share import batch_id_for, ensure_share_ready
from ..errors import IpcError, Unavailable, ValidationError
from ..protocol.identity import BrokerIdentity, verify_broker_identity
from ..storage import permissions
from ..util.ids import new_hex_id
from ..util.timeutil import format_iso
from .auth import issue_bearer

__all__ = [
    "AddedGrants",
    "WebCode",
    "WebUploadResult",
    "run_web_add_grants",
    "run_web_upload",
]

PACKAGE_FILES = {"payload.vspk", "upload-key.json", "package.json", "keyconfig.json", "policy.json"}


@dataclass(frozen=True)
class WebCode:
    grant_id: str
    code: str
    formatted: str
    used: int
    max_uses: int
    expires_at: int
    expires_text: str


@dataclass(frozen=True)
class WebUploadResult:
    package_id: str
    server: str
    policy_hash: str
    codes: list[WebCode]
    broker_fingerprint: str
    payload_size: int
    created: bool
    payload_mode: str = "server"


@dataclass(frozen=True)
class AddedGrants:
    package_id: str
    codes: list[WebCode]
    batch_id: str


def _basename(storage) -> str:
    return os.path.basename((storage.filename or "").replace("\\", "/"))


def _collect_files(
    upload_dir: Path, groups, *, local_payload: bool
) -> tuple[Path | None, Path, Path]:
    """把上传文件归位到临时目录，返回 (payload, keyconfig, policy)。

    ``local_payload=True`` 时不保存、也不需要 ``payload.vspk``：即使浏览器把
    文件发过来了，也直接丢弃，避免它落盘或再被上传。
    """
    package: dict[str, Path] = {}
    identity_json = []
    identity_key = []
    for group in groups:
        for storage in group:
            name = _basename(storage)
            if not name:
                continue
            if name in PACKAGE_FILES:
                if name == "payload.vspk" and local_payload:
                    continue
                if name in package:
                    raise ValidationError(f"重复上传了 {name}")
                target = upload_dir / name
                storage.save(str(target))
                package[name] = target
            elif name.lower().endswith(".key"):
                identity_key.append(storage)
            elif name.lower().endswith(".json"):
                identity_json.append(storage)
    if len(identity_json) != 1 or len(identity_key) != 1:
        raise ValidationError("请同时选择发送方身份 .json 与 .key 两个文件（各一个）")
    if not local_payload and "payload.vspk" not in package:
        raise ValidationError("缺少 payload.vspk（或勾选“本地交付”不上传密文）")
    if "package.json" not in package:
        raise ValidationError("缺少 package.json（加密工具生成的包信息文件）")
    deferred = "upload-key.json" in package
    prepared = "keyconfig.json" in package and "policy.json" in package
    if not deferred and not prepared:
        raise ValidationError("缺少 upload-key.json，或已准备包的 keyconfig.json / policy.json")

    identity_json[0].save(str(upload_dir / "identity.json"))
    identity_key[0].save(str(upload_dir / "identity.key"))
    permissions.tighten(str(upload_dir / "identity.key"))
    return (
        package.get("payload.vspk"),
        package.get("keyconfig.json", upload_dir / "keyconfig.json"),
        package.get("policy.json", upload_dir / "policy.json"),
    )


def _epoch(context) -> int:
    if context.store.degraded:
        raise Unavailable("状态处于降级模式，网页上传已暂停", code="state_corrupt")
    return int(context.store.snapshot()["body"]["auth"].get("api_epoch", 1))


def _broker_identity(context) -> BrokerIdentity:
    try:
        record = context.broker.call("get_identity", {})["identity"]
    except IpcError as exc:
        raise Unavailable("密钥代理暂不可用", code="broker_unavailable") from exc
    return verify_broker_identity(record)


def _api(client, token: str, method: str, path: str, **kwargs) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    headers.update(kwargs.pop("headers", {}))
    response = client.open(path, method=method, headers=headers, **kwargs)
    data = response.get_json(silent=True)
    if response.status_code >= 400:
        if isinstance(data, dict) and data.get("message"):
            raise ValidationError(str(data["message"]), code=str(data.get("error", "api_error")))
        raise ValidationError(f"服务器拒绝请求（HTTP {response.status_code}）")
    return data if isinstance(data, dict) else {}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_web_upload(
    context,
    *,
    username: str,
    remote_addr: str,
    package_files,
    identity_files,
    password: str,
    codes: int,
    max_uses: int,
    expires: str,
    local_payload: bool = False,
    max_codes: int | None = None,
) -> WebUploadResult:
    if not context.settings.web_upload:
        raise ValidationError(
            "网页上传未启用。请在服务器设置 VAULTSHARE_WEB_UPLOAD=1 后重启。"
        )
    if not password:
        raise ValidationError("请填写发送方身份私钥口令")
    payload_mode = "local" if local_payload else "server"

    with tempfile.TemporaryDirectory(prefix="vaultshare-web-upload-") as tmp:
        upload_dir = Path(tmp)
        payload_path, keyconfig_path, policy_path = _collect_files(
            upload_dir, (package_files, identity_files), local_payload=local_payload
        )
        keys: SenderKeys = load_identity(str(upload_dir / "identity"), password=password)
        broker_identity = _broker_identity(context)

        bundle = ensure_share_ready(
            str(upload_dir),
            keys,
            broker_identity,
            codes=int(codes),
            max_uses=int(max_uses),
            expires=expires,
            verify_payload=not local_payload,
            max_codes=max_codes,
        )
        package_id = str(bundle.get("package_id") or "")
        if not package_id:
            raise ValidationError("package.json 缺少 package_id")

        keyconfig = json.loads(Path(keyconfig_path).read_text(encoding="utf-8"))
        policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        if keyconfig.get("package_id") != package_id or policy.get("package_id") != package_id:
            raise ValidationError("KeyConfig / Policy 的 package_id 与包不一致")

        token, _expires = issue_bearer(context.secret, username, _epoch(context))
        client = current_app.test_client()

        _api(client, token, "post", "/api/v1/identity", json=keys.identity.record)
        created = False
        try:
            _api(
                client,
                token,
                "post",
                "/api/v1/packages",
                json={
                    "keyconfig": keyconfig,
                    "policy": policy,
                    "payload_mode": payload_mode,
                },
            )
            created = True
        except ValidationError as exc:
            if exc.code != "package_exists":
                raise

        public = _api(client, token, "get", f"/api/v1/packages/{package_id}/public")
        existing_mode = str(public.get("payload_mode") or "server")
        if existing_mode != payload_mode:
            raise ValidationError(
                "该 package_id 已按另一种交付方式创建（"
                f"服务器上为 {existing_mode}），请使用相同方式或换一个包。"
            )

        payload_size = 0
        if payload_mode == "server":
            if payload_path is None:  # 防御：上面已保证服务器交付必须有文件
                raise ValidationError("缺少 payload.vspk")
            payload_sha = _sha256_file(payload_path)
            payload_size = payload_path.stat().st_size
            existing_sha = str(public.get("payload_sha256") or "")
            if existing_sha:
                if existing_sha != payload_sha:
                    raise ValidationError("服务器上已存在摘要不同的 payload，拒绝覆盖")
            else:
                with open(payload_path, "rb") as fh:
                    _api(
                        client,
                        token,
                        "put",
                        f"/api/v1/packages/{package_id}/blob",
                        data=fh,
                        headers={
                            "Content-Type": "application/octet-stream",
                            "X-VaultShare-SHA256": payload_sha,
                            "X-VaultShare-Size": str(payload_size),
                        },
                    )

        batch_id = batch_id_for(package_id)
        grants_error: ValidationError | None = None
        try:
            _api(
                client,
                token,
                "post",
                f"/api/v1/packages/{package_id}/grants",
                json={
                    "count": int(bundle["codes"]),
                    "uses_per_code": int(bundle["max_uses"]),
                    "expires_at": int(bundle["expires_at"]),
                    "batch_id": batch_id,
                },
            )
        except ValidationError as exc:
            # 重复上传时口令可能已存在，但批次已经过期；只要还能读到口令就继续。
            grants_error = exc

        response = _api(client, token, "get", f"/api/v1/packages/{package_id}/codes")
        web_codes: list[WebCode] = []
        for grant in response.get("grants") or []:
            sealed = open_sealed_code(
                package_id,
                str(grant["grant_id"]),
                grant.get("sealed_code") or {},
                keys.x25519_private,
                keys.identity.x25519_public,
            )
            web_codes.append(
                WebCode(
                    grant_id=str(grant["grant_id"]),
                    code=sealed.code,
                    formatted=sealed.formatted,
                    used=int(grant.get("used", 0)),
                    max_uses=int(grant.get("max_uses", 0)),
                    expires_at=int(grant.get("expires_at", 0)),
                    expires_text=format_iso(int(grant.get("expires_at", 0))),
                )
            )
        if not web_codes:
            if grants_error is not None:
                raise grants_error
            raise ValidationError("没有生成任何口令，请检查策略参数或代理状态")

        context.audit(
            "web_upload",
            package_id=package_id,
            count=len(web_codes),
            by=username,
            ip=remote_addr,
            created=created,
            payload_mode=payload_mode,
        )
        return WebUploadResult(
            package_id=package_id,
            server=str(bundle.get("server") or ""),
            policy_hash=str(bundle.get("policy_hash") or ""),
            codes=web_codes,
            broker_fingerprint=broker_identity.fingerprint,
            payload_size=payload_size,
            created=created,
            payload_mode=payload_mode,
        )


def _save_identity_files(upload_dir: Path, files) -> None:
    """把用户选中的发送方身份 .json 与 .key 存到临时目录。"""
    identity_json = []
    identity_key = []
    for storage in files:
        name = _basename(storage)
        if name.lower().endswith(".key"):
            identity_key.append(storage)
        elif name.lower().endswith(".json"):
            identity_json.append(storage)
    if len(identity_json) != 1 or len(identity_key) != 1:
        raise ValidationError("请同时选择发送方身份 .json 与 .key 两个文件（各一个）")
    identity_json[0].save(str(upload_dir / "identity.json"))
    identity_key[0].save(str(upload_dir / "identity.key"))
    permissions.tighten(str(upload_dir / "identity.key"))


def run_web_add_grants(
    context,
    *,
    package_id: str,
    username: str,
    remote_addr: str,
    identity_files,
    password: str,
    codes: int,
    max_uses: int,
    expires: str,
) -> AddedGrants:
    """在已有包上继续签发口令。

    与网页上传一样，需要发送方私钥才能显示明文口令；Web 进程只在本次请求内
    接触私钥。身份必须与创建该包时使用的发送方一致，否则拒绝——避免把口令
    封给另一把密钥后谁也解不开。
    """
    if not context.settings.web_upload:
        raise ValidationError(
            "网页上传未启用。请在服务器设置 VAULTSHARE_WEB_UPLOAD=1 后重启。"
        )
    if not password:
        raise ValidationError("请填写发送方身份私钥口令")

    snapshot = context.store.snapshot()["body"]
    package = (snapshot.get("packages") or {}).get(package_id)
    if not isinstance(package, dict):
        raise ValidationError("包不存在", code="package_unknown")
    if package.get("status") != "active":
        raise ValidationError("包已撤销或不再有效，不能新增口令")

    with tempfile.TemporaryDirectory(prefix="vaultshare-web-grants-") as tmp:
        upload_dir = Path(tmp)
        _save_identity_files(upload_dir, identity_files)
        keys: SenderKeys = load_identity(
            str(upload_dir / "identity"), password=password
        )
        if (
            keys.identity.sender_key_id != package.get("sender_key_id")
            or keys.identity.digest != package.get("sender_identity_hash")
        ):
            raise ValidationError("身份文件与创建该包时使用的发送方不一致")

        token, _expires = issue_bearer(context.secret, username, _epoch(context))
        client = current_app.test_client()
        batch_id = new_hex_id(16)
        response = _api(
            client,
            token,
            "post",
            f"/api/v1/packages/{package_id}/grants",
            json={
                "count": int(codes),
                "uses_per_code": int(max_uses),
                "expires_in": str(expires),
                "batch_id": batch_id,
            },
        )
        new_ids = [
            str(item["grant_id"])
            for item in response.get("grants") or []
            if isinstance(item, dict) and item.get("grant_id")
        ]
        if not new_ids:
            raise ValidationError("没有生成任何口令，请检查策略参数或代理状态")

        listing = _api(
            client, token, "get", f"/api/v1/packages/{package_id}/codes"
        )
        by_id = {
            str(item.get("grant_id")): item
            for item in listing.get("grants") or []
            if isinstance(item, dict)
        }
        web_codes: list[WebCode] = []
        for grant_id in new_ids:
            grant = by_id.get(grant_id)
            if not isinstance(grant, dict):
                continue
            sealed = open_sealed_code(
                package_id,
                grant_id,
                grant.get("sealed_code") or {},
                keys.x25519_private,
                keys.identity.x25519_public,
            )
            web_codes.append(
                WebCode(
                    grant_id=grant_id,
                    code=sealed.code,
                    formatted=sealed.formatted,
                    used=int(grant.get("used", 0)),
                    max_uses=int(grant.get("max_uses", 0)),
                    expires_at=int(grant.get("expires_at", 0)),
                    expires_text=format_iso(int(grant.get("expires_at", 0))),
                )
            )
        if not web_codes:
            raise ValidationError("口令已生成，但无法解封显示；请用 CLI 查看")

        context.audit(
            "web_grants_added",
            package_id=package_id,
            count=len(web_codes),
            by=username,
            ip=remote_addr,
        )
        return AddedGrants(
            package_id=package_id, codes=web_codes, batch_id=batch_id
        )
