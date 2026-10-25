"""运行配置。

只从环境变量读取，避免把密钥或路径写进 Flask 配置对象后被调试页面/日志打印。
数据目录结构见 ``docs/STATE.md``。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"环境变量 {name} 必须是整数") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str
    port: int
    broker_host: str
    broker_port: int
    https: bool
    url_prefix: str = ""
    web_upload: bool = False
    session_timeout: int = 30 * 60
    upload_max_bytes: int = 8 * 1024**3
    upload_chunk_bytes: int = 1024 * 1024
    manifest_max_bytes: int = 1024 * 1024
    max_entries: int = 100_000

    # ---- 派生的数据路径 ----
    @property
    def packages_dir(self) -> Path:
        return self.data_dir / "packages"

    @property
    def brokers_dir(self) -> Path:
        return self.data_dir / "broker"

    @property
    def envelopes_dir(self) -> Path:
        return self.brokers_dir / "envelopes"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def broker_keys_dir(self) -> Path:
        return self.secrets_dir / "broker_keys"

    @property
    def locks_dir(self) -> Path:
        return self.data_dir / "locks"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def state_path(self) -> Path:
        return self.data_dir / "state.json"

    @property
    def journal_path(self) -> Path:
        return self.data_dir / "state.journal.jsonl"

    @property
    def checkpoint_path(self) -> Path:
        return self.data_dir / "journal.checkpoint.json"

    @property
    def senders_path(self) -> Path:
        return self.data_dir / "senders.json"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def notes_path(self) -> Path:
        """共享包与口令的备注（纯展示元数据，不参与校验）。"""
        return self.data_dir / "notes.json"

    @property
    def credentials_path(self) -> Path:
        return self.secrets_dir / "credentials.txt"

    @property
    def initial_credentials_path(self) -> Path:
        return self.secrets_dir / "INITIAL_CREDENTIALS.txt"

    @property
    def idempotency_path(self) -> Path:
        return self.brokers_dir / "idempotency.json"

    @property
    def flask_secret_path(self) -> Path:
        return self.secrets_dir / "flask_secret.key"

    @property
    def state_mac_path(self) -> Path:
        return self.secrets_dir / "state_mac.key"

    @property
    def ipc_hmac_path(self) -> Path:
        return self.secrets_dir / "ipc_hmac.key"

    @property
    def code_mac_path(self) -> Path:
        return self.secrets_dir / "code_mac.key"

    def ensure_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.packages_dir,
            self.brokers_dir,
            self.envelopes_dir,
            self.secrets_dir,
            self.broker_keys_dir,
            self.locks_dir,
            self.backups_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def normalize_url_prefix(raw: str) -> str:
    """把 ``VAULTSHARE_URL_PREFIX`` 归一化为 ``""`` 或 ``/foo/bar`` 形式。"""
    value = (raw or "").strip()
    if not value or value == "/":
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/")


def load_settings() -> Settings:
    raw = os.environ.get("VAULTSHARE_DATA", "").strip()
    data_dir = Path(raw).expanduser() if raw else PROJECT_ROOT / "data"
    return Settings(
        data_dir=data_dir.resolve(),
        host=os.environ.get("VAULTSHARE_HOST", "127.0.0.1"),
        port=_env_int("VAULTSHARE_PORT", 5000),
        broker_host=os.environ.get("VAULTSHARE_BROKER_HOST", "127.0.0.1"),
        broker_port=_env_int("VAULTSHARE_BROKER_PORT", 5051),
        https=_env_bool("VAULTSHARE_HTTPS", False),
        url_prefix=normalize_url_prefix(os.environ.get("VAULTSHARE_URL_PREFIX", "")),
        web_upload=_env_bool("VAULTSHARE_WEB_UPLOAD", False),
    )
