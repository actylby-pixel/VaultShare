"""代理密钥环。

每个 ``key_id`` 有两条原始私钥文件：``<key_id>.hpke.key``（X25519）与
``<key_id>.ed25519.key``（签名）。文件名与内容都不含版本或元数据；公钥由私钥
重新推导，永远不会从磁盘读取一个“声称的”公钥。

轮换只新增文件，不删除旧密钥：所有引用旧 ``key_id`` 的包在过期/撤销前仍要
能兑换。清理旧密钥必须人工确认（见 README）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..crypto import hpke
from ..crypto.keys import Ed25519Keys, read_private_key, write_private_key, x25519_public_bytes
from ..errors import Unavailable, ValidationError
from ..storage import permissions
from ..util.ids import KEY_ID_BYTES, is_hex_id, new_hex_id

__all__ = ["BrokerKeys", "KeyRing"]


@dataclass(frozen=True)
class BrokerKeys:
    key_id: str
    hpke_private: bytes
    hpke_public: bytes
    signing_private: bytes
    signing_public: bytes


class KeyRing:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.broker_keys_dir.mkdir(parents=True, exist_ok=True)
        permissions.tighten(str(self.settings.broker_keys_dir), directory=True)

    def _paths(self, key_id: str) -> tuple[Path, Path]:
        if not is_hex_id(key_id, KEY_ID_BYTES):
            raise ValidationError("key_id 格式非法")
        return (
            self.settings.broker_keys_dir / f"{key_id}.hpke.key",
            self.settings.broker_keys_dir / f"{key_id}.ed25519.key",
        )

    def list_ids(self) -> list[str]:
        ids = set()
        for name in os.listdir(self.settings.broker_keys_dir):
            if name.endswith(".hpke.key"):
                candidate = name[: -len(".hpke.key")]
                if is_hex_id(candidate, KEY_ID_BYTES):
                    ids.add(candidate)
        return sorted(ids)

    def load(self, key_id: str) -> BrokerKeys:
        hpke_path, sign_path = self._paths(key_id)
        if not hpke_path.exists() or not sign_path.exists():
            raise Unavailable("代理密钥不存在（可能已轮换或未初始化）")
        hpke_private = read_private_key(str(hpke_path))
        signing_private = read_private_key(str(sign_path))
        if len(hpke_private) != 32 or len(signing_private) != 32:
            raise Unavailable("代理密钥文件长度非法")
        ed = Ed25519Keys.from_private(signing_private)
        return BrokerKeys(
            key_id=key_id,
            hpke_private=hpke_private,
            hpke_public=x25519_public_bytes(hpke_private),
            signing_private=signing_private,
            signing_public=ed.public_bytes,
        )

    def generate(self) -> BrokerKeys:
        key_id = new_hex_id(KEY_ID_BYTES)
        hpke_private, hpke_public = hpke.generate_keypair()
        ed = Ed25519Keys.generate()
        hpke_path, sign_path = self._paths(key_id)
        write_private_key(str(hpke_path), hpke_private)
        write_private_key(str(sign_path), ed.private_bytes)
        permissions.tighten(str(hpke_path))
        permissions.tighten(str(sign_path))
        return BrokerKeys(
            key_id=key_id,
            hpke_private=hpke_private,
            hpke_public=hpke_public,
            signing_private=ed.private_bytes,
            signing_public=ed.public_bytes,
        )

    def ensure_initial(self) -> BrokerKeys:
        ids = self.list_ids()
        if ids:
            return self.load(ids[-1])
        return self.generate()
