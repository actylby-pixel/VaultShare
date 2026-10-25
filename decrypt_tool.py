"""打包 exe 用的解密工具入口脚本。

运行：``python decrypt_tool.py``

PyInstaller 示例（在 ``ff/`` 目录）::

    pyinstaller --noconfirm --onefile --windowed ^
      --name VaultShareDecrypt decrypt_tool.py
"""

from __future__ import annotations

from vaultshare.gui.decrypt_tool import main

if __name__ == "__main__":
    raise SystemExit(main())
