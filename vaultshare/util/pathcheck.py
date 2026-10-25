"""解包路径安全。

共享包里的路径来自发送方，接收方必须按最严格的口径处理，否则一个
``../../`` 或 Windows 的 ADS/保留设备名就能把文件写到输出目录之外，或者打开
本不该打开的设备。这里**同时**按 Windows 与 POSIX 的坏情况拒绝，不考虑运行
平台——一个包在 Windows 上解开过一次，就不该在 Linux 上换一套规则。

拒绝清单：
* 绝对路径、盘符（``C:``）、UNC（``\\\\``）、根路径；
* 反斜杠（统一要求正斜杠，避免两个平台解释不同）；
* ``.`` / ``..`` / 空组件；
* 任何 ``:``（NTFS 备用数据流）；
* Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含带扩展名形式）；
* 组件结尾的点或空格（Windows 会静默去掉，造成同名冲突）；
* 控制字符与 NUL；
* 单组件超过 255 字节、总路径超过 4096 字节。
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

__all__ = ["PathRejected", "validate_relpath", "ensure_within", "is_reparse_point"]

_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class PathRejected(ValueError):
    """包内路径不安全。"""


def _check_component(part: str) -> None:
    if not part or part in (".", ".."):
        raise PathRejected("路径包含空组件或 . / ..")
    if part.endswith(".") or part.endswith(" "):
        raise PathRejected(f"路径组件不能以点或空格结尾：{part!r}")
    if ":" in part:
        raise PathRejected(f"路径组件不能包含冒号：{part!r}")
    if any(ord(c) < 32 for c in part):
        raise PathRejected("路径组件包含控制字符")
    if len(part.encode("utf-8")) > 255:
        raise PathRejected("路径组件超过 255 字节")
    stem = part.split(".", 1)[0].upper()
    if stem in _RESERVED:
        raise PathRejected(f"路径使用了 Windows 保留设备名：{part!r}")


def validate_relpath(value: str) -> PurePosixPath:
    """校验并返回一个纯 POSIX 相对路径。"""
    if not isinstance(value, str) or not value:
        raise PathRejected("路径必须是非空字符串")
    if len(value.encode("utf-8")) > 4096:
        raise PathRejected("路径总长超过 4096 字节")
    if "\x00" in value:
        raise PathRejected("路径包含 NUL")
    if "\\" in value:
        raise PathRejected("路径必须使用正斜杠")
    if "//" in value:
        # pathlib 会悄悄合并连续斜杠；包内路径必须逐字节确定，不能依赖这种归一化。
        raise PathRejected("路径包含空组件")
    if value.startswith("/"):
        raise PathRejected("不允许绝对路径")
    if len(value) >= 2 and value[1] == ":":
        raise PathRejected("不允许盘符")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise PathRejected("不允许绝对路径")
    if not path.parts:
        raise PathRejected("路径为空")
    for part in path.parts:
        _check_component(part)
    return path


def ensure_within(
    root: str | os.PathLike,
    candidate: str | os.PathLike,
    *,
    allow_root: bool = False,
) -> str:
    """确认 ``candidate`` 的真实路径仍在 ``root`` 之内。

    用 ``realpath`` 而不是 ``abspath``：符号链接、目录联接、8.3 短名都会在
    真实路径层面暴露真实目标。比较使用 ``commonpath``。默认要求候选不是
    root 本身；检查“某个父目录”时可以传 ``allow_root=True``。
    """
    root_real = os.path.realpath(os.fspath(root))
    cand_real = os.path.realpath(os.fspath(candidate))
    try:
        common = os.path.commonpath([root_real, cand_real])
    except ValueError as exc:
        raise PathRejected("路径不在输出目录内") from exc
    if common != root_real:
        raise PathRejected("路径不在输出目录内")
    if cand_real == root_real and not allow_root:
        raise PathRejected("路径不在输出目录内")
    return cand_real


def is_reparse_point(path: str | os.PathLike) -> bool:
    """判断是否为符号链接/目录联接等重解析点。

    ``os.path.islink`` 覆盖符号链接；Windows 的目录联接（junction）在 Python
    里通常也能被 ``islink`` 识别，但用 ``st_file_attributes`` 再兜一层。
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & flag)


def assert_safe_target(out_dir: Path, rel: PurePosixPath) -> Path:
    """拼出目标路径并做包含性校验（不创建）。"""
    target = out_dir.joinpath(*rel.parts)
    ensure_within(out_dir, target)
    return target
