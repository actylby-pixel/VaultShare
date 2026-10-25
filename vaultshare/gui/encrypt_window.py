"""独立的加密工具窗口：只在本机加密，生成容器与上传凭据。"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
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

from .actions import EncryptInput, EncryptOutput, run_encrypt
from .common import (
    copy_text,
    dir_picker,
    file_picker,
    open_folder,
    password_edit,
    scroll_wrap,
)
from .workers import Worker

APP_TITLE = "VaultShare 加密工具"
UPLOAD_HINT = (
    "加密只在本地进行，不联网，也不在这里设置口令数量、次数与有效期；"
    "这些在上传时再决定。\n"
    "发送方身份：首次加密会用下面的口令生成“前缀.json”（公开身份）和"
    "“前缀.key”（私钥，供上传时解开 upload-key.json）。口令丢失后这个包就无法上传。"
)


class EncryptWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(640, 560)
        self.setMinimumSize(520, 420)
        self._worker: Worker | None = None
        self._busy = False
        self._last: EncryptOutput | None = None

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        notice = QLabel(
            "① 选择文件或文件夹并加密 ② 把 payload.vspk 发给对方 "
            "③ 收到口令后对方解密。服务器地址会写入容器，接收方无需填写。"
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

        inputs = QGroupBox("加密设置")
        form = QFormLayout(inputs)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("https://你的服务器（必须填写）")
        form.addRow("服务器地址", self.server_edit)

        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("要加密的文件或文件夹")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_edit)
        file_btn = QPushButton("选择文件…")
        file_btn.clicked.connect(
            lambda: file_picker(self, self.source_edit, "选择要加密的文件")
        )
        source_row.addWidget(file_btn)
        dir_btn = QPushButton("选择文件夹…")
        dir_btn.clicked.connect(
            lambda: dir_picker(self, self.source_edit, "选择要加密的文件夹")
        )
        source_row.addWidget(dir_btn)
        form.addRow("要加密的内容", source_row)

        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("输出目录，例如 .\\pkg（可以已存在）")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_btn = QPushButton("选择…")
        output_btn.clicked.connect(
            lambda: dir_picker(self, self.output_edit, "选择输出目录")
        )
        output_row.addWidget(output_btn)
        form.addRow("输出目录", output_row)

        self.prefix_edit = QLineEdit("sender")
        self.prefix_edit.setToolTip(
            "发送方身份文件名（不含扩展名）：会生成 sender.json 与 sender.key。\n"
            "上传时必须用同一身份和口令，才能解开 upload-key.json。"
        )
        form.addRow("身份文件前缀", self.prefix_edit)

        self.identity_pw = password_edit("私钥口令（首次填写即用于创建身份）")
        self.identity_pw.setToolTip(
            "用来加密 sender.key（Argon2id + AEAD）。忘记口令就无法上传这个包。"
        )
        form.addRow("身份私钥口令", self.identity_pw)

        self.require_fp_check = QCheckBox("要求接收方在解密前核对发送方指纹")
        self.require_fp_check.setChecked(True)
        self.require_fp_check.setToolTip(
            "勾选后，解密工具会要求接收方填写你通过可信渠道告知的发送方指纹，"
            "并核对服务器返回的身份记录。\n"
            "取消勾选则解密时不核对指纹，操作更简单，但若服务器被替换，"
            "接收方无法发现发送方身份被冒充。"
        )
        form.addRow("指纹核对", self.require_fp_check)
        layout.addWidget(inputs)

        hint = QLabel(UPLOAD_HINT)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid);")
        layout.addWidget(hint)

        buttons = QHBoxLayout()
        self.start_btn = QPushButton("开始加密")
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self._start)
        buttons.addWidget(self.start_btn)
        layout.addLayout(buttons)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        self.status_label = QLabel("就绪")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.result_box = QGroupBox("结果")
        result_form = QFormLayout(self.result_box)
        self.package_edit = QLineEdit()
        self.package_edit.setReadOnly(True)
        result_form.addRow("package_id", self.package_edit)
        self.sender_fp_edit = QLineEdit()
        self.sender_fp_edit.setReadOnly(True)
        result_form.addRow("发送方指纹", self.sender_fp_edit)
        self.container_edit = QLineEdit()
        self.container_edit.setReadOnly(True)
        result_form.addRow("加密容器", self.container_edit)
        self.upload_key_edit = QLineEdit()
        self.upload_key_edit.setReadOnly(True)
        result_form.addRow("上传凭据", self.upload_key_edit)
        self.identity_edit = QLineEdit()
        self.identity_edit.setReadOnly(True)
        result_form.addRow("发送方身份", self.identity_edit)
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        result_form.addRow("", self.summary_label)

        result_actions = QHBoxLayout()
        copy_btn = QPushButton("复制 package_id / 指纹")
        copy_btn.clicked.connect(self._copy_summary)
        result_actions.addWidget(copy_btn)
        open_btn = QPushButton("打开输出目录")
        open_btn.clicked.connect(self._open_output)
        result_actions.addWidget(open_btn)
        result_form.addRow("", result_actions)
        self.result_box.setVisible(False)
        layout.addWidget(self.result_box)
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

    def _collect(self) -> EncryptInput:
        data = EncryptInput(
            server=self.server_edit.text().strip(),
            source=self.source_edit.text().strip(),
            output=self.output_edit.text().strip(),
            identity_prefix=self.prefix_edit.text().strip(),
            identity_password=self.identity_pw.text(),
            require_sender_fingerprint=self.require_fp_check.isChecked(),
        )
        if not data.server:
            raise ValueError("请填写服务器地址（会写入加密容器）")
        if not data.source:
            raise ValueError("请选择要加密的文件或文件夹")
        if not data.output:
            raise ValueError("请选择输出目录")
        if not data.identity_prefix:
            raise ValueError("请填写身份文件前缀")
        if not data.identity_password:
            raise ValueError("请填写身份私钥口令")
        return data

    def _start(self) -> None:
        if self._busy:
            return
        try:
            data = self._collect()
        except ValueError as exc:
            QMessageBox.warning(self, "请检查输入", str(exc))
            return
        self._busy = True
        self._last = None
        self.result_box.setVisible(False)
        self._set_busy(True, "准备中…")
        worker = Worker(lambda status: run_encrypt(data, status))
        self._worker = worker
        worker.status.connect(self.status_label.setText)
        worker.succeeded.connect(self._done)
        worker.failed.connect(self._failed)
        worker.finished.connect(lambda: self._set_busy(False))
        worker.start()

    def _done(self, result: EncryptOutput) -> None:
        self._last = result
        self.package_edit.setText(result.package_id)
        self.sender_fp_edit.setText(result.sender_fingerprint)
        self.container_edit.setText(result.container_path)
        self.upload_key_edit.setText(result.upload_key_path)
        self.identity_edit.setText(
            f"{result.identity_public_path}  |  {result.identity_key_path}"
        )
        self.summary_label.setText(
            f"{result.manifest_files} 个文件，{result.manifest_bytes} 字节明文；"
            f"密文 {result.payload_size} 字节。\n"
            "接收方解密时需要核对发送方指纹："
            + ("是" if result.require_sender_fingerprint else "否")
        )
        self.result_box.setVisible(True)
        self.status_label.setText("加密完成（尚未上传）。")
        QMessageBox.information(
            self,
            "加密完成（尚未上传）",
            "本机已生成以下文件，网络上传还没有发生：\n\n"
            f"1. payload.vspk —— 加密容器，发给接收方：\n{result.container_path}\n\n"
            f"2. upload-key.json —— 上传凭据，留在这台电脑：\n{result.upload_key_path}\n\n"
            "3. package.json —— 包信息（package_id、摘要等），留在本机。\n\n"
            f"发送方身份：{result.identity_public_path}\n"
            f"            {result.identity_key_path}\n"
            "上传时需要这份身份文件和口令。\n\n"
            "以后用命令行 upload 上传时，再决定口令数量、次数与有效期。",
        )

    def _failed(self, message: str) -> None:
        self.status_label.setText("失败")
        QMessageBox.critical(self, "加密失败", message)

    def _copy_summary(self) -> None:
        if not self._last:
            QMessageBox.information(self, "没有结果", "请先完成加密。")
            return
        copy_text(
            f"package_id：{self._last.package_id}\n"
            f"服务器：{self._last.server}\n"
            f"发送方指纹：{self._last.sender_fingerprint}"
        )
        self.status_label.setText("package_id 与发送方指纹已复制。")

    def _open_output(self) -> None:
        path = self._last.output_dir if self._last else self.output_edit.text().strip()
        if path:
            open_folder(path)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._busy:
            QMessageBox.warning(self, "任务进行中", "请等待加密完成后再关闭窗口。")
            event.ignore()
            return
        event.accept()


def main(argv: list[str] | None = None) -> int:
    app = QApplication(argv if argv is not None else [])
    app.setApplicationName(APP_TITLE)
    window = EncryptWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
