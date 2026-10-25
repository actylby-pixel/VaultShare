"""独立的解密工具窗口：选择容器、填写口令、选择输出目录。

服务器地址与 package_id 从容器头部读取，服务器地址不显示；package_id 只读。
是否显示“发送方指纹”由发送方在加密时的选择决定（写在容器头部）。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .actions import DecryptInput, load_source_hint, run_decrypt
from .common import dir_picker, open_folder, scroll_wrap
from .workers import Worker

APP_TITLE = "VaultShare 解密工具"


class DecryptWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(640, 520)
        self.setMinimumSize(520, 380)
        self._worker: Worker | None = None
        self._busy = False
        self._kind = ""
        self._require_fp = True
        self._need_server = False

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        notice = QLabel(
            "① 选择发送方给你的加密容器 ② 填写兑换口令 ③ 选择输出目录。"
            "服务器地址与 package_id 会从容器自动读取，无需填写。"
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

        source_box = QGroupBox("① 选择加密容器")
        source_form = QFormLayout(source_box)
        self.source_edit = QLineEdit()
        self.source_edit.setReadOnly(True)
        self.source_edit.setPlaceholderText("payload.vspk（或分享卡片 .json）")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_edit)
        source_btn = QPushButton("打开…")
        source_btn.clicked.connect(self._pick_source)
        source_row.addWidget(source_btn)
        source_form.addRow("文件", source_row)
        self.source_hint = QLabel("尚未选择文件")
        self.source_hint.setWordWrap(True)
        source_form.addRow("", self.source_hint)
        layout.addWidget(source_box)

        details = QGroupBox("② 兑换信息")
        form = QFormLayout(details)
        self.package_edit = QLineEdit()
        self.package_edit.setReadOnly(True)
        self.package_edit.setPlaceholderText("从容器自动读取")
        form.addRow("package_id", self.package_edit)

        # 服务器地址默认不显示；只有旧版容器（头部没有地址）才让用户补填。
        self.server_box = QWidget()
        server_row = QHBoxLayout(self.server_box)
        server_row.setContentsMargins(0, 0, 0, 0)
        server_row.addWidget(QLabel("服务器地址"))
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("旧版容器没有地址时填写 https://…")
        server_row.addWidget(self.server_edit)
        form.addRow(self.server_box)
        self.server_box.setVisible(False)

        # 发送方在加密时要求核对指纹，才显示这一行。
        self.sender_fp_box = QWidget()
        fp_row = QHBoxLayout(self.sender_fp_box)
        fp_row.setContentsMargins(0, 0, 0, 0)
        fp_row.addWidget(QLabel("发送方指纹"))
        self.sender_fp_edit = QLineEdit()
        self.sender_fp_edit.setPlaceholderText("发送方通过可信渠道给你的 SHA-256")
        fp_row.addWidget(self.sender_fp_edit)
        form.addRow(self.sender_fp_box)
        self.sender_fp_box.setVisible(False)

        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText("发送方给你的 26 位口令")
        form.addRow("兑换口令", self.code_edit)

        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("解密到哪个空目录")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_btn = QPushButton("选择…")
        output_btn.clicked.connect(
            lambda: dir_picker(self, self.output_edit, "选择解密输出目录")
        )
        output_row.addWidget(output_btn)
        form.addRow("输出目录", output_row)
        layout.addWidget(details)

        actions = QHBoxLayout()
        self.start_btn = QPushButton("开始解密")
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self._start)
        actions.addWidget(self.start_btn)
        layout.addLayout(actions)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        self.status_label = QLabel("就绪")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)
        self.open_btn = QPushButton("打开输出目录")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(
            lambda: open_folder(self.output_edit.text().strip())
        )
        layout.addWidget(self.open_btn)
        layout.addStretch(1)

        self.setCentralWidget(scroll_wrap(inner))
        self.statusBar().showMessage("就绪")

    def is_busy(self) -> bool:
        return self._busy

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        self.start_btn.setEnabled(not busy)
        self.progress.setVisible(busy)
        if text:
            self.status_label.setText(text)

    def _pick_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择加密容器或分享卡片",
            self.source_edit.text().strip() or str(Path.home()),
            "VaultShare 文件 (*.vspk *.json *.vsshare);;所有文件 (*)",
        )
        if not path:
            return
        try:
            hint = load_source_hint(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "无法读取", str(exc))
            return

        self.source_edit.setText(path)
        self._kind = hint.kind
        self.package_edit.setText(hint.package_id)
        self.server_edit.setText(hint.server)

        # 旧版容器没有服务器地址，才显示补填框。
        self._need_server = hint.kind == "container" and not hint.server
        self._require_fp = bool(hint.require_sender_fingerprint)
        self.server_box.setVisible(self._need_server)
        self.sender_fp_box.setVisible(self._require_fp)
        self.sender_fp_edit.setText(hint.sender_fingerprint or "")

        if hint.kind == "card":
            self.source_hint.setText(
                "已读取分享卡片。"
                + ("卡片包含口令，已自动填入。" if hint.code else "请向发送方索取口令。")
            )
        elif not hint.server:
            self.source_hint.setText(
                "这个容器没有记录服务器地址（旧版容器），请在下方补填。"
            )
        elif hint.require_sender_fingerprint:
            self.source_hint.setText(
                "已从容器读取服务器与 package_id。"
                "发送方要求核对指纹，请填写他通过可信渠道告知的指纹。"
            )
        else:
            self.source_hint.setText(
                "已从容器读取服务器与 package_id。发送方未要求核对指纹。"
            )

        if hint.code:
            self.code_edit.setText(hint.code)
        if not self.output_edit.text().strip():
            self.output_edit.setText(str(Path(path).with_suffix("")) + "-解包")

    def _start(self) -> None:
        if self._busy:
            return
        if not self.source_edit.text().strip():
            QMessageBox.warning(self, "请检查输入", "请先选择加密容器。")
            return
        data = DecryptInput(
            server=self.server_edit.text().strip(),
            package_id=self.package_edit.text().strip(),
            code=self.code_edit.text().strip(),
            output=self.output_edit.text().strip(),
            sender_fingerprint=(
                self.sender_fp_edit.text().strip() if self._require_fp else ""
            ),
            # 分享卡片不是容器，交给 actions 用卡片里的服务器与 package_id。
            container=self.source_edit.text().strip() if self._kind == "container" else "",
        )
        self._set_busy(True, "准备中…")
        self.result_label.setText("")
        self.open_btn.setEnabled(False)
        worker = Worker(lambda status: run_decrypt(data, status))
        self._worker = worker
        worker.status.connect(self.status_label.setText)
        worker.succeeded.connect(self._done)
        worker.failed.connect(self._failed)
        worker.finished.connect(lambda: self._set_busy(False))
        worker.start()

    def _done(self, result) -> None:
        manifest = result.manifest or {}
        self.result_label.setText(
            f"解密完成：{manifest.get('total_files', '?')} 个文件，"
            f"{manifest.get('total_bytes', '?')} 字节 → {result.output_dir}"
        )
        self.status_label.setText("完成")
        self.open_btn.setEnabled(True)
        QMessageBox.information(self, "解密完成", "所有文件已校验并写入输出目录。")

    def _failed(self, message: str) -> None:
        self.status_label.setText("失败")
        QMessageBox.critical(self, "解密失败", message)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._busy:
            QMessageBox.warning(self, "任务进行中", "请等待解密完成后再关闭窗口。")
            event.ignore()
            return
        event.accept()


def main(argv: list[str] | None = None) -> int:
    app = QApplication(argv if argv is not None else [])
    app.setApplicationName(APP_TITLE)
    window = DecryptWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
