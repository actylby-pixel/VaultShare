# 构建 Windows 单文件 exe。
#
# 解密工具需要连接服务器，因此把自签名证书 qrlink.crt 一起打进 exe：
# 运行时它会作为默认信任锚（优先级：--ca-file > VAULTSHARE_CA_FILE > 包内证书）。
# 接收方只需要拿到 exe，不需要证书文件、不需要设置环境变量。
#
# 用法（在任意目录）：
#   .\ff\tools\build_exe.ps1              # 同时构建加密与解密工具
#   .\ff\tools\build_exe.ps1 -Tool decrypt
#   .\ff\tools\build_exe.ps1 -Cert D:\certs\other.crt
#
# 依赖：pip install pyinstaller（以及 requirements.txt / requirements-gui.txt）

param(
    [ValidateSet('decrypt', 'encrypt', 'both')]
    [string]$Tool = 'both',
    [string]$Python = '',
    [string]$Cert = ''
)

$ErrorActionPreference = 'Stop'

$ff = Split-Path $PSScriptRoot -Parent
$root = Split-Path $ff -Parent
if (-not $Python) { $Python = Join-Path $root 'key\Scripts\python.exe' }
if (-not $Cert) { $Cert = Join-Path $root 'qrlink.crt' }

if (-not (Test-Path $Python)) { throw "找不到 Python：$Python" }
if (-not (Test-Path $Cert)) { throw "找不到证书：$Cert（用 -Cert 指定）" }

$certPem = Get-Content $Cert -TotalCount 1
if ($certPem -notmatch 'BEGIN CERTIFICATE') {
    throw "$Cert 不是 PEM 证书（第一行应为 -----BEGIN CERTIFICATE-----）"
}

& $Python -m PyInstaller --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw '未安装 PyInstaller，请先运行：' + $Python + ' -m pip install pyinstaller'
}

$targets = @()
if ($Tool -in @('decrypt', 'both')) { $targets += @{ Script = 'decrypt_tool.py'; Name = 'VaultShare解密' } }
if ($Tool -in @('encrypt', 'both')) { $targets += @{ Script = 'encrypt_tool.py'; Name = 'VaultShare加密' } }

Push-Location $ff
try {
    foreach ($t in $targets) {
        Write-Host "==> 构建 $($t.Name)（内置证书 $Cert）"
        & $Python -m PyInstaller --noconfirm --clean --onefile --windowed `
            --name $t.Name `
            --add-data "$Cert;." `
            --paths $ff `
            $t.Script
        if ($LASTEXITCODE -ne 0) { throw "构建 $($t.Name) 失败" }
    }
}
finally {
    Pop-Location
}

Write-Host ''
Write-Host "完成，输出在 $ff\dist："
Get-ChildItem (Join-Path $ff 'dist') -Filter *.exe | ForEach-Object { Write-Host "  $($_.FullName)" }
Write-Host ''
Write-Host '提示：证书已打包进 exe；换证书需要重新构建。接收方无需任何额外配置。'
