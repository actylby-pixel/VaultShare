"""两个独立 GUI 共用的控件与小工具。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QLineEdit,
    QScrollArea,
    QWidget,
)

__all__ = [
    "dir_picker",
    "file_picker",
    "open_folder",
    "copy_text",
    "password_edit",
    "scroll_wrap",
]


def dir_picker(parent: QWidget, edit: QLineEdit, title: str) -> None:
    start = edit.text().strip() or str(Path.home())
    path = QFileDialog.getExistingDirectory(parent, title, start)
    if path:
        edit.setText(path)


def file_picker(parent: QWidget, edit: QLineEdit, title: str) -> None:
    start = edit.text().strip() or str(Path.home())
    path, _selected = QFileDialog.getOpenFileName(parent, title, start)
    if path:
        edit.setText(path)


def open_folder(path: str) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(path))


def copy_text(text: str) -> None:
    QApplication.clipboard().setText(text)


def password_edit(placeholder: str = "") -> QLineEdit:
    edit = QLineEdit()
    edit.setEchoMode(QLineEdit.EchoMode.Password)
    edit.setPlaceholderText(placeholder)
    return edit


def scroll_wrap(inner: QWidget) -> QScrollArea:
    """让表单在较小屏幕上可滚动，窗口本身仍可调整大小。"""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidget(inner)
    return area
