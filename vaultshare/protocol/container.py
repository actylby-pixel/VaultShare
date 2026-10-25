"""``payload.vspk`` 容器：打包文件或目录为加密流，并安全解包。

单文件包只在 manifest 中放一条文件条目（路径为文件名）；目录包保留相对路径。


v3 布局::

    header = MAGIC "VSPK"(4) | version=3(1) | package_id(16) | suite(2) |
             flags(1) | server_url_len(u16 BE) | server_url(UTF-8) |
             secretstream_header(24)
    然后重复 [u32 BE ct_len][ciphertext]，最后一条带 TAG_FINAL。

``flags`` 第 0 位（``CONTAINER_FLAG_REQUIRE_SENDER_FP``）表示发送方要求接收方
核对发送方身份指纹。它是**发送方的偏好声明**，不是密码学信任锚：flag 也受
AAD 保护，但只有拿到 ``K_pkg`` 之后才能验证；在此之前攻击者若能替换整个容器，
同样能改写这个 flag。接收方工具据此决定是否显示并强制指纹输入。

v2（仅读取兼容）没有 ``flags`` 字段，按“必须核对指纹”处理；v1 既没有
``server_url_len`` / ``server_url``，也没有 flags，header 固定 47 字节。
服务器地址只是方便接收方少输一次地址的**提示**，不是信任锚；地址位于 AAD
覆盖范围内，取得 ``K_pkg`` 后一旦被改动就会认证失败。

AAD = 完整 header || msg_index_u32be || ct_len_u32be。

明文流的第一条消息是 ``u32 manifest_len || manifest_json``，之后按 manifest
中文件顺序拼接文件字节。manifest 自身也加密并受 AAD 保护。

解包规则（全部是拒绝条件，不做“尽量修一下”）：
* 路径按 ``util.pathcheck`` 的 Windows+POSIX 双重规则校验；
* 大小写冲突、文件/目录同名冲突拒绝；
* 实际字节数与 manifest 不一致拒绝；
* 解完后仍有剩余明文字节拒绝；
* 写入使用 O_EXCL，绝不覆盖已有文件。
"""

from __future__ import annotations

import json
import mimetypes
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Iterator

from ..crypto.kdf import stream_key
from ..crypto.memsec import wipe
from ..crypto.stream import (
    CHUNK,
    StreamError,
    decrypt_chunks,
    encrypt_chunks,
    read_exactly,
)
from ..errors import ValidationError
from ..util.canonical import canonical_bytes, sha256_hex
from ..util.ids import PKG_ID_BYTES, is_hex_id
from ..util.pathcheck import (
    PathRejected,
    ensure_within,
    is_reparse_point,
    validate_relpath,
)
from ..util.serverurl import MAX_SERVER_URL_BYTES, normalize_server_url
from ..version import (
    CONTAINER_FLAG_REQUIRE_SENDER_FP,
    CONTAINER_MAGIC,
    CONTAINER_VERSION,
    CONTAINER_VERSION_V1,
    CONTAINER_VERSION_V2,
    PROTOCOL_VERSION,
    STREAM_SUITE_ID,
)
from .signing import require_int, require_str

__all__ = [
    "MANIFEST_FORMAT",
    "ContainerMeta",
    "PackResult",
    "build_manifest",
    "make_header_prefix",
    "pack_directory",
    "read_container_header",
    "read_container_meta",
    "unpack_container",
    "make_aad",
]

MANIFEST_FORMAT = "vaultshare-manifest"
# v1: magic|version|package_id|suite + secretstream_header
HEADER_V1_LEN = 4 + 1 + PKG_ID_BYTES + 2 + 24
# v2: magic|version|package_id|suite|url_len|url + secretstream_header
HEADER_V2_FIXED_LEN = 4 + 1 + PKG_ID_BYTES + 2 + 2
# v3: magic|version|package_id|suite|flags|url_len|url + secretstream_header
HEADER_V3_FIXED_LEN = 4 + 1 + PKG_ID_BYTES + 2 + 1 + 2
KNOWN_CONTAINER_FLAGS = CONTAINER_FLAG_REQUIRE_SENDER_FP
STREAM_HEADER_LEN = 24
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ENTRIES = 100_000
MAX_TOTAL_BYTES = 8 * 1024**3
_ENTRY_FIELDS = {"path", "type", "size", "mime"}


@dataclass(frozen=True)
class ContainerMeta:
    version: int
    package_id: str
    server_url: str
    header: bytes
    # 发送方是否要求接收方核对发送方身份指纹。v1/v2 没有该字段，按 True 处理。
    require_sender_fingerprint: bool = True


@dataclass(frozen=True)
class PackResult:
    manifest: dict
    plaintext_bytes: int
    ciphertext_bytes: int
    manifest_sha256: str


def make_header_prefix(
    package_id: str,
    server_url: str = "",
    *,
    require_sender_fingerprint: bool = True,
) -> bytes:
    """构造 v3 头部（不含 24 字节 secretstream header）。"""
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    url = normalize_server_url(server_url)
    url_bytes = url.encode("utf-8")
    if len(url_bytes) > MAX_SERVER_URL_BYTES:
        raise ValidationError("服务器地址过长")
    flags = CONTAINER_FLAG_REQUIRE_SENDER_FP if require_sender_fingerprint else 0
    return (
        CONTAINER_MAGIC
        + bytes([CONTAINER_VERSION])
        + bytes.fromhex(package_id)
        + int(STREAM_SUITE_ID).to_bytes(2, "big")
        + bytes([flags])
        + len(url_bytes).to_bytes(2, "big")
        + url_bytes
    )


def make_aad(header: bytes, msg_index: int, ct_len: int) -> bytes:
    return header + msg_index.to_bytes(4, "big") + ct_len.to_bytes(4, "big")


def _entry_fields_ok(entry) -> bool:
    if not isinstance(entry, dict) or set(entry.keys()) != _ENTRY_FIELDS:
        return False
    if entry.get("type") not in ("file", "dir"):
        return False
    size = entry.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return False
    if entry["type"] == "dir" and size != 0:
        return False
    if not isinstance(entry.get("mime"), str) or len(entry["mime"]) > 255:
        return False
    return True


def _manifest_for_file(path: Path, package_id: str) -> dict:
    """单个文件的包：manifest 里只有一条文件条目，路径就是文件名。"""
    if os.path.islink(path) or is_reparse_point(path):
        raise ValidationError(f"拒绝打包符号链接：{path}")
    if not os.path.isfile(path):
        raise ValidationError(f"拒绝打包特殊文件：{path}")
    rel = path.name
    validate_relpath(rel)
    size = int(os.lstat(path).st_size)
    if size > MAX_TOTAL_BYTES:
        raise ValidationError("明文总量超过上限")
    mime = mimetypes.guess_type(rel)[0] or "application/octet-stream"
    manifest = {
        "format": MANIFEST_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "entries": [{"path": rel, "type": "file", "size": size, "mime": mime}],
        "total_files": 1,
        "total_bytes": size,
    }
    if len(canonical_bytes(manifest)) > MAX_MANIFEST_BYTES:
        raise ValidationError("manifest 超过大小上限")
    return manifest


def build_manifest(root: str | os.PathLike, package_id: str) -> dict:
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    root_path = Path(root)
    if root_path.is_file():
        return _manifest_for_file(root_path, package_id)
    if not root_path.is_dir():
        raise ValidationError("源路径必须是文件或目录")
    entries = []
    seen: set[str] = set()
    total_bytes = 0
    root_real = os.path.realpath(root_path)

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        dirnames.sort()
        filenames.sort()
        # 不进入符号链接/重解析点，也不把它们放进包。
        kept_dirs = []
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                raise ValidationError(f"拒绝打包符号链接：{full}")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in kept_dirs:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root_path).replace(os.sep, "/")
            entries.append(_dir_entry(rel, seen))
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                raise ValidationError(f"拒绝打包符号链接：{full}")
            stat = os.lstat(full)
            if not os.path.isfile(full):
                raise ValidationError(f"拒绝打包特殊文件：{full}")
            rel = os.path.relpath(full, root_path).replace(os.sep, "/")
            validate_relpath(rel)
            key = rel.casefold()
            if key in seen:
                raise ValidationError(f"大小写冲突的路径：{rel}")
            seen.add(key)
            size = int(stat.st_size)
            total_bytes += size
            mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
            entries.append({"path": rel, "type": "file", "size": size, "mime": mime})
            if len(entries) > MAX_ENTRIES:
                raise ValidationError("条目数超过上限")
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValidationError("明文总量超过上限")
        if len(entries) > MAX_ENTRIES:
            raise ValidationError("条目数超过上限")

    entries.sort(key=lambda e: e["path"])
    manifest = {
        "format": MANIFEST_FORMAT,
        "version": PROTOCOL_VERSION,
        "package_id": package_id,
        "entries": entries,
        "total_files": sum(1 for e in entries if e["type"] == "file"),
        "total_bytes": total_bytes,
    }
    if len(canonical_bytes(manifest)) > MAX_MANIFEST_BYTES:
        raise ValidationError("manifest 超过大小上限")
    return manifest


def _dir_entry(rel: str, seen: set[str]) -> dict:
    validate_relpath(rel)
    key = rel.casefold()
    if key in seen:
        raise ValidationError(f"大小写冲突的路径：{rel}")
    seen.add(key)
    return {"path": rel, "type": "dir", "size": 0, "mime": ""}


def _file_chunks(path: Path, size: int) -> Iterator[bytes]:
    remaining = size
    with open(path, "rb") as f:
        while remaining > 0:
            block = f.read(min(CHUNK, remaining))
            if not block:
                raise ValidationError(f"文件在打包过程中被截断：{path.name}")
            remaining -= len(block)
            yield block
        if f.read(1):
            raise ValidationError(f"文件在打包过程中增长：{path.name}")


def pack_directory(
    src: str | os.PathLike,
    out_path: str | os.PathLike,
    k_pkg: bytes,
    package_id: str,
    *,
    server_url: str = "",
    require_sender_fingerprint: bool = True,
    progress=None,
) -> PackResult:
    """流式打包；先写临时文件，成功后再原子替换。失败不留下半个包。

    ``server_url`` 会写进头部（AAD 覆盖），用于提示接收方服务器地址。
    ``require_sender_fingerprint`` 写入头部 flags，表示发送方是否要求接收方
    在兑换前核对发送方身份指纹。
    """
    manifest = build_manifest(src, package_id)
    manifest_bytes = canonical_bytes(manifest)
    header_prefix = make_header_prefix(
        package_id,
        server_url,
        require_sender_fingerprint=require_sender_fingerprint,
    )
    key = stream_key(k_pkg, bytes.fromhex(package_id))
    source = Path(src)
    # 单文件包：manifest 里的路径是文件名，读取时以文件所在目录为根。
    root = source.parent if source.is_file() else source
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(out_path.parent), prefix="." + out_path.name + ".", suffix=".tmp"
    )

    def chunks() -> Iterator[bytes]:
        yield len(manifest_bytes).to_bytes(4, "big") + manifest_bytes
        for entry in manifest["entries"]:
            if entry["type"] != "file":
                continue
            yield from _file_chunks(root / PurePosixPath(entry["path"]), entry["size"])

    try:
        with os.fdopen(fd, "wb") as dst:
            _header, written = encrypt_chunks(
                chunks(),
                dst,
                key,
                header_prefix,
                make_aad,
                progress=(lambda n: progress(n)) if progress else None,
            )
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp, out_path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    finally:
        wipe(key)

    return PackResult(
        manifest=manifest,
        plaintext_bytes=written,
        ciphertext_bytes=out_path.stat().st_size,
        manifest_sha256=sha256_hex(manifest_bytes),
    )


def read_container_meta(src: BinaryIO) -> ContainerMeta:
    """只读取头部，返回版本、包 ID、服务器地址提示与指纹核对要求。"""
    head = read_exactly(src, 5)
    if head[:4] != CONTAINER_MAGIC:
        raise ValidationError("不是 VSPK 容器")
    version = head[4]
    if version == CONTAINER_VERSION_V1:
        header = head + read_exactly(src, HEADER_V1_LEN - 5)
        if int.from_bytes(header[21:23], "big") != STREAM_SUITE_ID:
            raise ValidationError("不支持的容器套件")
        return ContainerMeta(
            version=version,
            package_id=header[5:21].hex(),
            server_url="",
            header=header,
            require_sender_fingerprint=True,
        )
    if version == CONTAINER_VERSION_V2:
        base = head + read_exactly(src, HEADER_V2_FIXED_LEN - 5)
        if int.from_bytes(base[21:23], "big") != STREAM_SUITE_ID:
            raise ValidationError("不支持的容器套件")
        url_len = int.from_bytes(base[23:25], "big")
        if url_len > MAX_SERVER_URL_BYTES:
            raise ValidationError("容器头部的服务器地址过长")
        url_bytes = read_exactly(src, url_len)
        stream_header = read_exactly(src, STREAM_HEADER_LEN)
        server_url = _decode_server_url(url_bytes)
        return ContainerMeta(
            version=version,
            package_id=base[5:21].hex(),
            server_url=server_url,
            header=base + url_bytes + stream_header,
            # v2 没有 flags 字段，保持旧行为：必须核对指纹。
            require_sender_fingerprint=True,
        )
    if version != CONTAINER_VERSION:
        raise ValidationError("不支持的容器版本")
    base = head + read_exactly(src, HEADER_V3_FIXED_LEN - 5)
    if int.from_bytes(base[21:23], "big") != STREAM_SUITE_ID:
        raise ValidationError("不支持的容器套件")
    flags = base[23]
    if flags & ~KNOWN_CONTAINER_FLAGS:
        raise ValidationError("容器头部包含未知标志位")
    url_len = int.from_bytes(base[24:26], "big")
    if url_len > MAX_SERVER_URL_BYTES:
        raise ValidationError("容器头部的服务器地址过长")
    url_bytes = read_exactly(src, url_len)
    stream_header = read_exactly(src, STREAM_HEADER_LEN)
    server_url = _decode_server_url(url_bytes)
    return ContainerMeta(
        version=version,
        package_id=base[5:21].hex(),
        server_url=server_url,
        header=base + url_bytes + stream_header,
        require_sender_fingerprint=bool(flags & CONTAINER_FLAG_REQUIRE_SENDER_FP),
    )


def _decode_server_url(url_bytes: bytes) -> str:
    try:
        return normalize_server_url(url_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValidationError("容器头部的服务器地址不是 UTF-8") from exc


def read_container_header(src: BinaryIO, package_id: str) -> bytes:
    meta = read_container_meta(src)
    if meta.package_id != package_id.lower():
        raise ValidationError("容器 package_id 与预期不一致")
    return meta.header


class _StreamReader:
    """把解密消息序列拼成可精确读取的字节流。"""

    def __init__(self, messages: Iterable[bytes]):
        self._it = iter(messages)
        self._buf = bytearray()
        self._eof = False

    def _fill(self, n: int) -> None:
        while len(self._buf) < n and not self._eof:
            try:
                self._buf.extend(next(self._it))
            except StopIteration:
                self._eof = True

    def read_exact(self, n: int) -> bytes:
        self._fill(n)
        if len(self._buf) < n:
            raise ValidationError("容器已结束，但文件数据不足")
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def drain(self) -> bytes:
        while not self._eof:
            try:
                self._buf.extend(next(self._it))
            except StopIteration:
                self._eof = True
        out = bytes(self._buf)
        self._buf.clear()
        return out


def _validate_manifest(manifest: dict, package_id: str) -> list[dict]:
    if not isinstance(manifest, dict):
        raise ValidationError("manifest 不是 JSON 对象")
    if manifest.get("format") != MANIFEST_FORMAT or manifest.get("version") != PROTOCOL_VERSION:
        raise ValidationError("manifest 版本非法")
    if manifest.get("package_id") != package_id:
        raise ValidationError("manifest package_id 不匹配")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValidationError("manifest 条目列表非法")
    seen: set[str] = set()
    total = 0
    for entry in entries:
        if not _entry_fields_ok(entry):
            raise ValidationError("manifest 条目结构非法")
        rel = validate_relpath(entry["path"])
        key = str(rel).casefold()
        if key in seen:
            raise ValidationError("manifest 存在重复或大小写冲突路径")
        seen.add(key)
        total += entry["size"]
        if total > MAX_TOTAL_BYTES:
            raise ValidationError("manifest 声明总量超过上限")
    if manifest.get("total_bytes") != total:
        raise ValidationError("manifest 总大小字段不一致")
    if manifest.get("total_files") != sum(1 for e in entries if e["type"] == "file"):
        raise ValidationError("manifest 文件数字段不一致")
    return entries


def unpack_container(
    src_path: str | os.PathLike,
    staging_dir: str | os.PathLike,
    k_pkg: bytes,
    package_id: str,
    *,
    progress=None,
) -> dict:
    """解密到**新建**的 staging 目录；返回 manifest。

    调用方负责把 staging 中的内容提交到最终位置，并在失败时删除 staging。
    这里不跟随任何链接，且每个目标都用 ``ensure_within`` 再核对一次。
    """
    if not is_hex_id(package_id, PKG_ID_BYTES):
        raise ValidationError("package_id 格式非法")
    staging = Path(staging_dir)
    if staging.exists() and any(staging.iterdir()):
        raise ValidationError("staging 目录必须为空")
    staging.mkdir(parents=True, exist_ok=True)
    key = stream_key(k_pkg, bytes.fromhex(package_id))
    try:
        with open(src_path, "rb") as src:
            header = read_container_header(src, package_id)
            messages = decrypt_chunks(
                src,
                key,
                header,
                make_aad,
                progress=(lambda n: progress(n)) if progress else None,
            )
            reader = _StreamReader(messages)
            try:
                first = reader.read_exact(4)
            except ValidationError as exc:
                raise ValidationError("容器缺少 manifest") from exc
            manifest_len = int.from_bytes(first, "big")
            if manifest_len <= 0 or manifest_len > MAX_MANIFEST_BYTES:
                raise ValidationError("manifest 长度非法")
            manifest_bytes = reader.read_exact(manifest_len)
            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("manifest 不是合法 JSON") from exc
            entries = _validate_manifest(manifest, package_id)

            for entry in entries:
                rel = validate_relpath(entry["path"])
                target = staging.joinpath(*rel.parts)
                ensure_within(staging, target)
                if entry["type"] == "dir":
                    target.mkdir(parents=True, exist_ok=True)
                    ensure_within(staging, target)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                ensure_within(staging, target.parent, allow_root=True)
                with open(target, "xb") as f:
                    remaining = entry["size"]
                    while remaining > 0:
                        block = reader.read_exact(min(CHUNK, remaining))
                        f.write(block)
                        remaining -= len(block)
            extra = reader.drain()
            if extra:
                raise ValidationError("容器在声明的文件数据之后仍有剩余内容")
        return manifest
    except PathRejected as exc:
        raise ValidationError(f"不安全的包内路径：{exc}") from exc
    except StreamError as exc:
        raise ValidationError(f"容器解密失败：{exc}") from exc
    finally:
        wipe(key)
