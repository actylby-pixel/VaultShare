"""以子进程运行 GUI 动作层验收脚本（真实 HTTP + IPC，不创建窗口）。"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ff" / "tools" / "gui_flow_check.py"


class GuiFlowTests(unittest.TestCase):
    def test_gui_actions_end_to_end(self) -> None:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["VAULTSHARE_DATA"] = str(
            Path(env.get("TEMP", ".")) / "vaultshare-gui-flow-subprocess"
        )
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        self.assertEqual(completed.returncode, 0, output[-4000:])
        self.assertIn("GUI 全链路通过", output)


if __name__ == "__main__":
    unittest.main()
