"""以子进程方式跑完整端到端脚本（真实 HTTP + IPC + 临时数据目录）。"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ff" / "tools" / "e2e_check.py"


class EndToEndTests(unittest.TestCase):
    def test_e2e_script_succeeds(self) -> None:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        # 脚本自己会设置临时 VAULTSHARE_DATA；这里显式覆盖，确保绝不碰真实 data/。
        env["VAULTSHARE_DATA"] = str(Path(env.get("TEMP", ".")) / "vaultshare-e2e-subprocess")
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
        self.assertIn("E2E 全部通过", output)


if __name__ == "__main__":
    unittest.main()
