"""打包 exe 用的加密工具入口脚本。

运行：``python encrypt_tool.py``

PyInstaller 示例（在 ``ff/`` 目录）::

    pyinstaller --noconfirm --onefile --windowed ^
      --name VaultShareEncrypt encrypt_tool.py
"""

from __future__ import annotations

from vaultshare.gui.encrypt_tool import main

if __name__ == "__main__":
    raise SystemExit(main())
