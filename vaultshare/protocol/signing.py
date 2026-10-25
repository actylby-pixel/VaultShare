"""签名与 HPKE 上下文绑定的共用规则。

HPKE 的 ``info`` 用长度前缀编码：``u32(len(domain))||domain`` 后接若干
``u32(len(field))||field``。这与 RFC 9180 的 ``aad`` 是**不同位置**的绑定
（``info`` 进入 key schedule），但同样提供认证；改动任一字段都会导致解封
失败。原因与完整说明见 ``docs/PROTOCOL.md``。

为了兼容 RFC 9180 的“上下文绑定必须在 AEAD 层”这一直觉，本协议把每个用途
的域标签放在 info 的第一个字段，且不同用途的标签互不相同。跨用途重放（例如
把口令密文当兑换请求提交）会被 HPKE 本身的认证拒绝。
"""

from __future__ import annotations

from ..crypto.keys import (
    DOMAIN_AUTHORIZATION,
    DOMAIN_GRANT_BATCH,
    DOMAIN_UPLOAD_KEY,
    DOMAIN_KEYCONFIG,
    DOMAIN_POLICY,
    DOMAIN_RECEIPT,
    DOMAIN_SENDER_IDENTITY,
    sign_object,
    verify_object,
)
from ..errors import ValidationError
from ..util.canonical import fixed_domain

__all__ = [
    "sign_object",
    "verify_object",
    "DOMAIN_KEYCONFIG",
    "DOMAIN_POLICY",
    "DOMAIN_SENDER_IDENTITY",
    "DOMAIN_RECEIPT",
    "DOMAIN_AUTHORIZATION",
    "DOMAIN_GRANT_BATCH",
    "DOMAIN_UPLOAD_KEY",
    "keyconfig_info",
    "redeem_info",
    "code_info",
    "envelope_info",
    "authorization_info",
    "upload_key_info",
    "require_int",
    "require_str",
    "require_b64",
]
from ..util.canonical import b64u_decode


def keyconfig_info(package_id: bytes, policy_hash: bytes) -> bytes:
    return fixed_domain(b"VaultShare/kc/v1", package_id, policy_hash)


def redeem_info(package_id: bytes) -> bytes:
    return fixed_domain(b"VaultShare/redeem/v1", package_id)


def upload_key_info(
    package_id: bytes,
    payload_sha256: bytes,
    sender_identity_hash: bytes,
    server_url: bytes,
) -> bytes:
    """上传凭据中密封 ``K_pkg`` 的 HPKE 上下文。

    绑定包 ID、容器摘要、发送方身份与服务器地址；任一字段不同都无法解封。
    """
    return fixed_domain(
        b"VaultShare/upload-key/v1",
        package_id,
        payload_sha256,
        sender_identity_hash,
        server_url,
    )


def code_info(package_id: bytes, grant_id: bytes, sender_x25519_pk: bytes) -> bytes:
    return fixed_domain(b"VaultShare/code/v1", package_id, grant_id, sender_x25519_pk)


def envelope_info(
    package_id: bytes,
    grant_id: bytes,
    request_id: bytes,
    recipient_pk_hash: bytes,
    config_version: int,
) -> bytes:
    return fixed_domain(
        b"VaultShare/envelope/v1",
        package_id,
        grant_id,
        request_id,
        recipient_pk_hash,
        int(config_version).to_bytes(4, "big"),
    )


def authorization_info(authorization_id: str) -> bytes:
    return fixed_domain(b"VaultShare/authorization/v1", authorization_id.encode("ascii"))


def require_int(value, name: str, minimum: int | None = None, maximum: int | None = None) -> int:
    if not isinstance(value, bool) and isinstance(value, int):
        result = value
    else:
        raise ValidationError(f"{name} 必须是整数")
    if minimum is not None and result < minimum:
        raise ValidationError(f"{name} 小于允许值")
    if maximum is not None and result > maximum:
        raise ValidationError(f"{name} 大于允许值")
    return result


def require_str(value, name: str, *, max_len: int = 4096, empty_ok: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} 必须是字符串")
    if not empty_ok and not value:
        raise ValidationError(f"{name} 不能为空")
    if len(value) > max_len:
        raise ValidationError(f"{name} 过长")
    return value


def require_b64(value, name: str, expected_len: int | None = None) -> bytes:
    try:
        return b64u_decode(value, expected_len=expected_len)
    except ValueError as exc:
        raise ValidationError(f"{name} 不是合法的 base64url") from exc
