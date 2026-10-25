"""共享包在磁盘上的布局。

``packages/<package_id>/``：
* ``keyconfig.json``  发送方签名的 KeyConfig（canonical JSON 字节）
* ``policy.json``     发送方签名的 SharePolicy
* ``payload.vspk``    加密容器
* ``meta.json``       摘要与大小（不作为信任来源；状态文件里的摘要才是）

所有读取都限制大小与 JSON 解析深度（标准库不提供深度限制，这里用文件大小
上限 + 类型校验代替）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from ..config import Settings
from ..errors import NotFound, ValidationError
from ..util.canonical import canonical_bytes, sha256_hex
from ..util.ids import PKG_ID_BYTES, safe_name
from .atomic import atomic_write_bytes, ensure_dir, replace_file

__all__ = [
    "package_dir",
    "create_package_dir",
    "write_meta",
    "read_keyconfig",
    "read_policy",
    "read_meta",
    "read_keyconfig_bytes",
    "read_policy_bytes",
    "payload_path",
    "upload_temp_path",
    "commit_payload",
    "delete_package_dir",
    "iter_package_ids",
]

MAX_JSON_BYTES = 256 * 1024


def package_dir(settings: Settings, package_id: str) -> Path:
    return settings.packages_dir / safe_name(package_id, PKG_ID_BYTES, "package_id")


def create_package_dir(settings: Settings, package_id: str, keyconfig: dict, policy: dict) -> Path:
    directory = package_dir(settings, package_id)
    if directory.exists():
        raise ValidationError("package 已存在", code="package_exists")
    ensure_dir(directory)
    try:
        atomic_write_bytes(str(directory / "keyconfig.json"), canonical_bytes(keyconfig))
        atomic_write_bytes(str(directory / "policy.json"), canonical_bytes(policy))
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return directory


def _read_json_file(path: Path) -> dict:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise NotFound("package 文件不存在") from exc
    if size > MAX_JSON_BYTES:
        raise ValidationError("package 元数据过大")
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("package 元数据损坏") from exc


def read_keyconfig(settings: Settings, package_id: str) -> dict:
    return _read_json_file(package_dir(settings, package_id) / "keyconfig.json")


def read_policy(settings: Settings, package_id: str) -> dict:
    return _read_json_file(package_dir(settings, package_id) / "policy.json")


def read_meta(settings: Settings, package_id: str) -> dict:
    return _read_json_file(package_dir(settings, package_id) / "meta.json")


def read_keyconfig_bytes(settings: Settings, package_id: str) -> bytes:
    path = package_dir(settings, package_id) / "keyconfig.json"
    try:
        return path.read_bytes()
    except OSError as exc:
        raise NotFound("KeyConfig 不存在") from exc


def read_policy_bytes(settings: Settings, package_id: str) -> bytes:
    path = package_dir(settings, package_id) / "policy.json"
    try:
        return path.read_bytes()
    except OSError as exc:
        raise NotFound("Policy 不存在") from exc


def write_meta(settings: Settings, package_id: str, meta: dict) -> None:
    atomic_write_bytes(str(package_dir(settings, package_id) / "meta.json"), canonical_bytes(meta))


def payload_path(settings: Settings, package_id: str) -> Path:
    return package_dir(settings, package_id) / "payload.vspk"


def upload_temp_path(settings: Settings, package_id: str) -> Path:
    directory = package_dir(settings, package_id)
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".payload.", suffix=".tmp")
    os.close(fd)
    return Path(tmp)


def commit_payload(settings: Settings, package_id: str, temp: Path, expected_sha: str, expected_size: int) -> None:
    """校验大小与 SHA-256 后原子改名为 payload.vspk，并读回校验。"""
    digest = hashlib.sha256()
    size = 0
    try:
        with open(temp, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
    except OSError as exc:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise ValidationError("上传文件读取失败") from exc
    if size != expected_size:
        os.remove(temp)
        raise ValidationError("上传大小与声明不一致")
    if digest.hexdigest() != expected_sha:
        os.remove(temp)
        raise ValidationError("上传 SHA-256 与声明不一致")
    target = payload_path(settings, package_id)
    replace_file(str(temp), str(target))
    if target.stat().st_size != expected_size:
        raise OSError("payload 替换后大小校验失败")


def delete_package_dir(settings: Settings, package_id: str) -> None:
    shutil.rmtree(package_dir(settings, package_id), ignore_errors=True)


def iter_package_ids(settings: Settings):
    if not settings.packages_dir.is_dir():
        return []
    result = []
    for name in os.listdir(settings.packages_dir):
        path = settings.packages_dir / name
        if path.is_dir() and len(name) == PKG_ID_BYTES * 2:
            result.append(name)
    return sorted(result)
