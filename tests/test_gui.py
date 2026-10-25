"""GUI 冒烟测试：每个工具在独立子进程离屏构建（不在测试进程加载 Qt）。"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ff" / "tools" / "gui_smoke_check.py"


class GuiSmokeTests(unittest.TestCase):
    def _run(self, mode: str) -> None:
        env = dict(os.environ)
        env["QT_QPA_PLATFORM"] = "offscreen"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), mode],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        self.assertEqual(completed.returncode, 0, output[-2000:])
        self.assertIn(f"GUI SMOKE OK ({mode})", output)

    def test_encrypt_window_builds(self) -> None:
        self._run("encrypt")

    def test_decrypt_window_builds(self) -> None:
        self._run("decrypt")


if __name__ == "__main__":
    unittest.main()
