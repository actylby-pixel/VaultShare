"""把耗时动作放到 QThread，避免界面卡死。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QThread, Signal

__all__ = ["Worker"]


class Worker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)
    status = Signal(str)

    def __init__(self, fn: Callable[[Callable[[str], None]], Any], parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D401 - Qt 回调
        try:
            result = self._fn(self.status.emit)
        except Exception as exc:  # noqa: BLE001 - 统一展示给用户
            message = str(exc) or exc.__class__.__name__
            self.failed.emit(message)
        else:
            self.succeeded.emit(result)
