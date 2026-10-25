"""GUI 离屏冒烟检查：每个进程只构建一个窗口，与“两个独立程序”一致。

``test_gui`` 分别以子进程调用 ``encrypt`` / ``decrypt``。单独运行::

    ..\\key\\Scripts\\python.exe tools\\gui_smoke_check.py encrypt
    ..\\key\\Scripts\\python.exe tools\\gui_smoke_check.py decrypt
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ff"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def main(mode: str) -> int:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QScrollArea, QTabWidget

    from ff.vaultshare.gui.decrypt_window import DecryptWindow
    from ff.vaultshare.gui.encrypt_window import EncryptWindow

    if mode == "encrypt":
        factory, title = EncryptWindow, "加密工具"
    elif mode == "decrypt":
        factory, title = DecryptWindow, "解密工具"
    else:
        raise SystemExit("用法：gui_smoke_check.py encrypt|decrypt")

    app = QApplication.instance() or QApplication([])
    window = factory()
    window.show()
    app.processEvents()
    assert title in window.windowTitle(), window.windowTitle()
    assert window.is_busy() is False
    assert isinstance(window.centralWidget(), QScrollArea)
    assert window.findChild(QTabWidget) is None
    assert app is not None

    # 走一遍真实事件循环再正常退出。注意不能在 Qt 对象仍存活时 os._exit：
    # Windows 上 ExitProcess 卸载 Qt DLL 会偶发访问违例（0xC0000005）。
    QTimer.singleShot(0, app.quit)
    app.exec()
    print(f"GUI SMOKE OK ({mode})", flush=True)
    return 0


def _exit_without_qt_teardown(code: int) -> None:
    """结束冒烟子进程，跳过 Qt 的 DLL 卸载。

    Windows 上 Qt 在解释器清理阶段卸载 DLL 时偶尔触发 0xC0000005；此时所有
    断言与事件循环都已完成，崩溃发生在 teardown，和被测窗口无关。直接以目标
    退出码终止进程，让测试结果稳定。非 Windows 仍走正常退出。
    """
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel32.TerminateProcess.restype = ctypes.c_int
        kernel32.TerminateProcess(kernel32.GetCurrentProcess(), int(code))
    raise SystemExit(code)


if __name__ == "__main__":
    mode_arg = sys.argv[1] if len(sys.argv) > 1 else "encrypt"
    try:
        code = main(mode_arg)
    except BaseException as exc:  # noqa: BLE001 - 冒烟脚本统一报错
        print(f"GUI SMOKE FAILED: {type(exc).__name__}: {exc}", flush=True)
        code = 1
    _exit_without_qt_teardown(code)
