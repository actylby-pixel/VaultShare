# VaultShare v1

独立部署的加密文件分享服务：发送方把目录打包成只对密钥代理和接收方可见的
密文，接收方凭一次性口令在服务器协助下取得密钥并解密。密文默认放在服务器，
也可以选择“本地交付”：服务器只保存元数据与口令，容器由发送方直接给接收方
（见 §4.4.1）。服务端是 Flask 单用户
应用（用户名 + 密码 + TOTP），密钥由独立的本地代理进程保管，状态使用 JSON
文件持久化，**不使用数据库**。

```
ff/
  README.md                本文件
  requirements.txt         Flask / cryptography / PyNaCl / pyotp / qrcode / waitress
  .env.example             环境变量示例
  vaultshare/              实现代码
    cli.py                 统一命令行入口
    server/                Flask Web + JSON API
    broker/                密钥代理进程、IPC、密钥环
    protocol/              KeyConfig、Policy、信封、容器等线格式
    crypto/                HPKE、AEAD、KDF、secretstream 封装
    storage/               状态、锁、原子写、审计、包存储
    client/                CLI 客户端（身份、打包、上传、兑换）
    gui/                   两个独立图形界面（加密工具 / 解密工具）
  encrypt_tool.py          加密工具打包入口（PyInstaller 用）
  decrypt_tool.py          解密工具打包入口（PyInstaller 用）
  docs/
    PROTOCOL.md            线格式、HPKE 上下文、兑换状态机
    STATE.md               state.json、journal、锁、崩溃恢复
    SECURITY.md            信任边界、密钥轮换、审计、残余风险
  tests/                   单元、并发、多进程、Web、端到端测试
  tools/e2e_check.py       完整端到端验收脚本
  data/                    运行时数据（默认位置，已 gitignore）
```

> **安全边界一句话**：密钥代理是**普通软件进程，不是 TEE**。拥有服务器
> root/管理员权限的攻击者仍可能读取密钥；本版本只提供进程隔离与纵深防御。
> 详见 [docs/SECURITY.md](docs/SECURITY.md)。

---

## 1. 特性

- 单用户网页认证：用户名 + 密码（scrypt 哈希）+ 6 位 TOTP，凭证文件可用记事本
  编辑；首次启动自动生成并只显示一次。
- 发送方身份把 Ed25519（签名）与 X25519（口令密文）绑定在一条自我签名记录中；
  接收方用带外核对的指纹 (TOFU) 验证服务器返回的一切。
- 每包随机 `K_pkg`；口令 26 位 Crockford Base32，服务器只保存 HMAC 验证值，
  明文口令只用发送方公钥密封后离开代理。
- HPKE 固定套件（X25519 + HKDF-SHA256 + AES-128-GCM）封装 `K_pkg`、兑换请求、
  口令与交付信封；所有绑定上下文放进 `info`（与 RFC 9180 的 `aad` 偏差见
   文档）。
- 三阶段兑换：预授权 → 提交预留（唯一扣减点）→ 代理验证已提交预留后交付。
  额度占用永不回滚；同一 `request_id` 重试返回字节一致的信封且不重复扣减。
- 无数据库：状态文件带完整信封 MAC，journal + 检查点 + 原子替换；损坏时进入
  降级模式，禁止兑换，绝不自动重置授权或提升 `.bak`。
- 单写者锁、每事务状态锁、崩溃/磁盘写失败恢复、跨进程并发测试。
- CLI 覆盖「加密 → 上传 → 领取口令 → 兑换 → 验回执 → 解密」全链路。
- 可选 PySide6 图形界面，拆成**两个独立程序**：加密工具只在本机加密，解密工具
  只负责兑换解密；可分别打包成两个 exe。服务器地址写入容器头部，接收方打开
  容器即可自动填充。
- 加密与分享策略分离：加密时生成 `upload-key.json`（密封的 `K_pkg`），上传时
  再决定口令数量、次数与有效期。

---

## 2. 安装

要求 Python 3.11+、Windows 或 Linux、本地磁盘（不支持 NFS/SMB 共享状态）。

python.exe -m pip install -r requirements.txt

# 需要图形界面时（可选）
python.exe -m pip install -r requirements-gui.txt
```

`cryptography` 固定为 `50.0.2`：HPKE API 的 `info` 语义在该版本上经过测试。
升级前请重新运行 HPKE 交叉测试。

---

## 3. 首次启动

### 3.1 启动服务与代理

# 终端 1：Web 服务（首次启动会生成账号、随机密码、TOTP 密钥）
python.exe -m vaultshare.cli server run --host 127.0.0.1 --port 5000

# 终端 2：密钥代理
python.exe -m vaultshare.cli broker run
```

- 首次启动生成用户名 `admin`、24 字符随机密码、TOTP 密钥。
- 标准输出是终端时：打印一次密码与 `otpauth://` URI（含终端二维码）。
- 非交互运行（systemd/服务）时：凭证写入
  `data/secrets/INITIAL_CREDENTIALS.txt`（权限收紧），控制台只打印路径。
  读取后执行 `vaultshare admin ack-init` 删除；未删除前登录页显示告警。
- 代理启动时打印 `key_id` 与指纹；指纹必须通过可信渠道核对。

浏览器访问 `http://127.0.0.1:5000/login`，输入用户名、密码与 TOTP。登录后可以：

- **概览**：包/口令/次数/发送方统计、代理状态、最近事件；
- **共享包**：全部包列表与详情（含每个口令的用量、撤销入口）；
- **发送方**：已注册身份与指纹；
- **审核日志**：最近事件（完整记录在 `data/audit.jsonl`）；
- **系统**：状态代数/降级原因、代理指纹、密钥文件是否存在、维护命令；
- **上传**（可选，默认隐藏）：把加密工具的输出直接传到服务器并生成口令。
  默认关闭，因为启用后 Web 进程会短暂接触发送方私钥与 `K_pkg`；见 4.5。

网页本身不显示明文口令，也不运行任何 JavaScript（CSP `script-src 'none'`）。
默认仍建议用 CLI 上传、发码与兑换。

### 3.2 配置

通过环境变量（见 `.env.example`）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `VAULTSHARE_DATA` | `ff/data` | 数据目录 |
| `VAULTSHARE_HOST` / `VAULTSHARE_PORT` | `127.0.0.1` / `5000` | Web 监听 |
| `VAULTSHARE_BROKER_HOST` / `VAULTSHARE_BROKER_PORT` | `127.0.0.1` / `5051` | 代理监听（只允许回环） |
| `VAULTSHARE_HTTPS` | `0` | 反向代理终结 TLS 时设为 `1` |
| `VAULTSHARE_URL_PREFIX` | 空 | 部署在子路径时填 `/vault`（配合反向代理） |
| `VAULTSHARE_WEB_UPLOAD` | `0` | 开启网页上传；**改变信任边界**，见 4.5 |
| `VAULTSHARE_IDENTITY_PASSWORD` | 空 | 发送方私钥口令（CLI 自动化用） |
| `VAULTSHARE_USERNAME` / `VAULTSHARE_PASSWORD` | 空 | CLI 登录（优先于交互输入） |
| `VAULTSHARE_CA_FILE` | 空 | 客户端只信任该 PEM 证书/CA（自签名部署用），见 3.3 |

### 3.3 自签名证书：只信任你这一个证书

客户端**始终验证 TLS**，没有“忽略证书错误”开关。如果服务器用自签名证书，
可以把这张证书指定为唯一信任锚：此时只加载该文件，**不再加载系统根证书**，
任何其他证书（包括其他自签名证书和公共 CA）都会被拒绝。

```powershell
# 命令行：每个需要连服务器的子命令都支持 --ca-file
..\key\Scripts\python.exe -m vaultshare.cli redeem `
  --package <package_id> --code XXXX-... --out .\解包 `
  --server https://192.168.2.1:8800/vault `
  --ca-file .\server.crt `
  --sender-fingerprint <fingerprint>

# 或者一次设置环境变量，CLI 与图形界面都会自动使用
$env:VAULTSHARE_CA_FILE = "E:\certs\server.crt"
```

- `--ca-file` 优先于环境变量；文件不存在会立刻报错，而不是悄悄回退到系统根证书。
- 打包的 exe 可以把证书内置（见 4.7 的构建脚本），此时优先级是
  `--ca-file` > `VAULTSHARE_CA_FILE` > 内置证书 > 系统根证书。
- 图形界面（`encrypt_tool.py` / `decrypt_tool.py`）与打包后的 exe 没有命令行参数，
  用环境变量 `VAULTSHARE_CA_FILE` 指定证书路径。
- 文件是 PEM 格式的证书本身（`.crt` / `.pem`），不是私钥。
- 证书里的 SAN 必须包含你实际访问的主机名或 IP（例如 `IP:192.168.2.1`），否则
  即使证书受信任也会因主机名不匹配而失败。
- 这台证书不是 CA 也可以：直接把服务器证书当作信任锚即可（`openssl x509`
  或导出 `.cer` → 另存为 Base64/PEM）。

---

## 4. 端到端流程（CLI）

以下命令均在 `ff/` 目录执行。

### 4.1 核对代理身份（打包前必须）

```powershell
..\key\Scripts\python.exe -m vaultshare.cli broker info `
  --server http://127.0.0.1:5000 `
  --fingerprint <从代理终端或可信渠道取得的 SHA-256> `
  --out broker-identity.json
```

不带 `--fingerprint` 时会提示“未核对”，仅适合本地测试。`pack` 会重新计算
指纹并比对；不一致拒绝打包。

### 4.2 创建并注册发送方身份

```powershell
python.exe -m vaultshare.cli identity init --path sender
python.exe -m vaultshare.cli identity show --path sender
python.exe -m vaultshare.cli identity register --path sender `
  --server http://127.0.0.1:5000
```

- `sender.json`：可公开的自我签名身份记录；
- `sender.key`：Ed25519 + X25519 私钥，Argon2id + XChaCha20-Poly1305 加密；
- `identity show` 输出的 `fingerprint` 需要交给接收方（可信渠道）。

### 4.3 只加密（推荐）

```powershell
python.exe -m vaultshare.cli encrypt .\资料 `
  --identity sender `
  --server http://127.0.0.1:5000 `
  --out .\pkg
```

`encrypt` 的源可以是**一个文件或一个目录**；`--out` 可以已存在、也可以有别
的文件，只会拒绝覆盖同名的 `payload.vspk` / `upload-key.json` / `package.json`。

输出目录包含：

- `payload.vspk`：加密容器，**发给接收方**；服务器地址与是否要求核对指纹
  已写进头部（v3），接收方打开时无需再输入地址；
- `upload-key.json`：上传凭据，内含用发送方公钥密封的 `K_pkg`，**留在本机**；
- `package.json`：包 ID、容器摘要等元数据。

加密不联网，也不决定口令数量/次数/有效期（这些在上传时确定）。
加密结束会自动用 `K_pkg` 完整解密一遍，验证容器可读。

> 兼容说明：旧的 `pack` 命令仍可一次性生成完整共享包（含 KeyConfig/Policy），
> 适合已知分享策略的场景；新流程建议使用 `encrypt` + 上传时定策略。

### 4.4 上传并生成口令

```powershell
..\key\Scripts\python.exe -m vaultshare.cli upload .\pkg `
  --identity sender --server http://127.0.0.1:5000 `
  --broker-identity broker-identity.json `
  --codes 2 --max-uses 3 --expires 7d
```

对 `encrypt` 生成的包，上传时会：

1. 核对 `upload-key.json` 的签名、身份绑定、容器摘要与服务器地址；
2. 用发送方私钥解封 `K_pkg`，完整验证容器；
3. 按 `--codes/--max-uses/--expires` 生成并签名 Policy/KeyConfig；
4. 登录（密码 + TOTP）→ 注册身份 → 上传密文（本地交付时跳过）→ 代理发码
   → 本地解封口令。

重复执行不会改变已签名的策略，也不会重复扣减额度。`--broker-identity` 建议
始终提供；省略时会从服务器读取代理身份，但会打印“未带外核对”的警告。

可选写出分享卡片（默认不含口令）：

```powershell
python.exe -m vaultshare.cli upload .\pkg `
  --identity sender --server http://127.0.0.1:5000 `
  --broker-identity broker-identity.json `
  --codes 2 --max-uses 3 --expires 7d `
  --card .\share-card.json
```

之后可随时查看：

```powershell
python.exe -m vaultshare.cli codes `
  --package <package_id> --identity sender --server http://127.0.0.1:5000
```

#### 4.4.1 本地交付：服务器不接收密文

默认的上传会把 `payload.vspk` 存到服务器，接收方兑换时再下载。文件很大时这
意味着一次多余的完整上传。加 `--local-payload` 后，服务器只保存 KeyConfig、
Policy 与口令，**完全不接收密文**；发送方自己把 `payload.vspk` 交给接收方
（网盘、U 盘、聊天工具等）：

```powershell
..\key\Scripts\python.exe -m vaultshare.cli upload .\pkg `
  --identity sender --server http://127.0.0.1:5000 `
  --broker-identity broker-identity.json `
  --codes 2 --max-uses 3 --expires 7d `
  --local-payload
```

- 接收方仍然必须先拿到有效口令才能取得 `K_pkg`；服务器只保存密封后的口令与
  密钥信封，安全边界不变。
- 解密时把容器一并给出：图形界面直接选择 `payload.vspk`；CLI 用
  `--container <payload.vspk>`（见 §4.6）。
- 解密前会先核对容器头部的 `package_id`；若服务器声明过尺寸/SHA-256（服务器
  交付的包），也会逐一比对，不一致就拒绝，且**不会消耗口令次数**。
- 同一个 `package_id` 不能在两种交付方式之间混用：重复上传时若方式不同会直接
  报错，请换一个新的包或沿用原来的方式。
- 网页上传也能勾选“本地交付”而不保存密文；但浏览器仍会把你选中的文件发给
  Web 进程，大文件请用上面的 CLI 参数，那条路径完全不传输密文。

### 4.5 网页上传（可选，默认关闭）

设置 `VAULTSHARE_WEB_UPLOAD=1` 并重启服务后，导航栏会出现“上传”。在页面里选择
`upload-key.json`、`package.json`（服务器交付时再加 `payload.vspk`），再选择
发送方身份的 `sender.json` / `sender.key`（也可以和包文件一起选中），输入私钥
口令、口令数量、每个口令次数、**口令总数上限**与有效期，提交即可。服务器会：

1. 在临时目录里用口令解开身份私钥，验证 `upload-key.json` 的签名与身份绑定；
2. 解封 `K_pkg`，并按本次参数生成签名 Policy / KeyConfig；
3. 通过内部 Bearer API 注册身份、创建包、上传密文（仅服务器交付）、让代理发码；
4. 用发送方公钥解开密封口令，**只在结果页显示一次**。

勾选“本地交付”后，服务器不会保存或上传密文，只创建元数据与口令；你需要自己
把加密工具生成的 `payload.vspk` 交给接收方。注意浏览器仍会把文件选择框里选中
的所有文件发给 Web 进程，所以本地交付时**不要选择** `payload.vspk`；多 GB 文件
请用 CLI `--local-payload`，那条路径完全不传输密文。

风险与限制：

- **信任边界改变**：Web 进程会接触发送方私钥与 `K_pkg` 明文，不再是“服务器永远
  拿不到密钥”。详细说明见 `docs/SECURITY.md` 第 3.2 节。
- 只建议在完全由你掌控、且已启用 HTTPS 的服务器上开启；否则请继续用 CLI 上传。
- 临时文件在请求结束时删除；口令、私钥与 `K_pkg` 不写日志、不写状态文件。
- 已准备过的包（含 `keyconfig.json` / `policy.json`）会复用已签名策略，页面上的
  口令数量/次数/有效期以包内策略为准。
- 上传仍然只接受加密工具的产物，服务器不解密文件内容。

**口令总数上限**（默认 50）会写进发送方签名的 `SharePolicy.max_codes`，为后续
“增加口令”预留额度；本次仍只生成“本次生成口令数”那几条。上限只能在上传时
设定，之后无法放宽（策略是签名的，服务器不能改）。`max_total_redemptions` 随之
设为 `上限 × 每个口令可用次数`。

**备注**：上传页可以为整个包写一条备注（≤500 字），结果页可以为刚显示的每条
口令写备注。备注只是展示用的元数据，保存在 `data/notes.json`，**不参与任何签名
或授权校验**，也不影响包/口令的可用性；包详情页可以随时修改包备注或批量修改
口令备注。备注是明文存储的，不要写入口令、私钥密码等敏感信息。

**在包详情页增加口令**：包仍为 `active` 时，详情页底部有“增加口令”面板。需要
再次选择**与该包相同的发送方身份** `.json` / `.key` 并输入私钥口令（原因同上传：
要解封口密封口令才能显示明文）。服务器会拒绝身份不一致、包已撤销或超出
`max_codes` / `max_total_redemptions` 的请求。新增的口令同样只在本次结果页显示
一次明文。该功能依赖网页上传开关，`VAULTSHARE_WEB_UPLOAD=0` 时不可用。

关闭网页上传不会影响 CLI 上传，也不会删除任何入口之外的功能。

### 4.6 接收方兑换

```powershell
python.exe -m vaultshare.cli redeem `
  --package <package_id> --code XXXXXXXXX-... `
  --out .\解包目录 `
  --server http://127.0.0.1:5000 `
  --sender-fingerprint <identity show 的 fingerprint> `
  --broker-fingerprint <代理指纹>
```

接收方本地会：

1. 验证发送方身份记录与 KeyConfig/Policy 的签名和绑定；
2. 核对发送方指纹（TOFU）与代理指纹（CLI 始终要求发送方指纹；图形界面
   按容器头部的 `require_sender_fingerprint` 标记决定，见 §4.7）；
3. 生成临时 X25519 密钥并 HPKE 封装兑换请求；
4. 验证回执签名、`envelope_core` 摘要与全部绑定字段；
5. 解封 `K_pkg`、取得密文、解密到临时目录，全部成功后才提交到输出目录。

密文来源取决于包的交付方式：服务器交付的包自动下载 `/blob`；本地交付的包
（`--local-payload` 上传）必须另外给出发送方的容器：

```powershell
python.exe -m vaultshare.cli redeem `
  --package <package_id> --code XXXXXXXXX-... `
  --out .\解包目录 --container .\payload.vspk `
  --server http://127.0.0.1:5000 `
  --sender-fingerprint <identity show 的 fingerprint>
```

`--container` 也可以用于服务器交付的包：直接解密本地容器，省去下载。无论哪种
方式，容器都会先校验 `package_id` 与（服务器有声明时的）尺寸/SHA-256，校验
失败不会消耗次数。

同一 `request_id` 的重试由 CLI 在单次调用内自助完成；服务端对重试返回同一
信封且不重复扣减次数。

服务器用自签名证书时，给上面的命令加 `--ca-file 路径\server.crt`，或设置
`VAULTSHARE_CA_FILE`（见 3.3）。

### 4.7 图形界面（两个独立工具，可选）

安装 `requirements-gui.txt` 后，在 `ff/` 目录分别运行：

```powershell
python.exe encrypt_tool.py   # 加密工具
python.exe decrypt_tool.py   # 解密工具
```

也可以运行 `python -m vaultshare.gui.encrypt_tool` 或
`python -m vaultshare.gui.decrypt_tool`。
两个窗口内容都放在滚动区域里，小屏幕也能操作；关闭窗口即丢弃所有输入。

**加密工具**只在本机加密，不登录、不上传：

1. 填写服务器地址（只写入容器，供接收方自动填充）；
2. 选择要加密的**文件或文件夹**，再选输出目录（可以已存在、可以有别的文件）；
3. 填写身份文件前缀与私钥口令（首次自动创建身份）；
4. 按需取消“要求接收方在解密前核对发送方指纹”（默认勾选；勾选时解密工具
   会强制填写指纹，取消则解密时不核对）；
5. 点击“开始加密”，得到 `payload.vspk`（发给对方）、`upload-key.json`
   与 `package.json`（后两个留本机）。

自签名证书部署时，先设置 `VAULTSHARE_CA_FILE` 再启动图形界面（见 3.3）；
解密工具连接服务器时只信任该证书。

身份文件是 `前缀.json`（公开身份）和 `前缀.key`（用口令加密的私钥）；上传时
必须用同一身份和口令解开 `upload-key.json`，口令丢失就无法上传。结果区会显示
这两个文件的完整路径。

口令数量、次数与有效期不在这里设置；上传时用 CLI 决定。界面不保存密码、
口令或私钥。

**解密工具**只需三步：

1. 选择 `payload.vspk`（或分享卡片 `.json`）：服务器地址与 package_id 自动
   从容器读取，服务器地址不显示，package_id 只读；
2. 填写兑换口令；
3. 选择输出目录，点击“开始解密”。

发送方在加密时勾选了“要求核对指纹”时，界面才会出现“发送方指纹”一栏并强制
填写；未勾选时该栏完全不显示，解密不做指纹比对。无论是否显示，发送方身份
记录自签名、KeyConfig/Policy 签名与绑定、代理签名与回执验证都照常执行。

容器里的服务器地址与指纹核对标记都只是提示/偏好：能替换整个容器的攻击者
可以改写它们。需要防止服务器冒充发送方时，仍应通过可信渠道核对发送方指纹
（或让发送方勾选该选项）。



## 6. 数据结构

运行时使用 `data/`（可通过 `VAULTSHARE_DATA` 改位置）：

- `state.json`：权威状态（带 MAC），包含发送方、包、grant、兑换请求、限额计数；
- `state.journal.jsonl` / `journal.checkpoint.json`：崩溃回放与压实；
- `packages/<id>/`：KeyConfig、Policy、`payload.vspk`（本地交付的包没有此文件）；
- 发送方本地的包目录还可能含 `upload-key.json`（密封的 `K_pkg`，仅上传用）
  与可选的 `share-card.json`；
- `secrets/`：凭证、TOTP、代理私钥、MAC/IPC/会话密钥；
- `broker/`：幂等记录与信封缓存；
- `notes.json`：包与口令的备注（明文、非安全元数据，不参与校验，可随时删除）；
- `audit.jsonl`：追加式审计。

完整字段、锁语义、原子写顺序与恢复流程见 [docs/STATE.md](docs/STATE.md)。

---

## 7. 运维

### 备份

```powershell
..\key\Scripts\python.exe -m vaultshare.cli admin backup
```

备份包含状态、journal、检查点、审计与凭证文件，按敏感数据保管。恢复必须人工
确认，且需先停止服务：

```powershell
..\key\Scripts\python.exe -m vaultshare.cli admin recover --from-journal --confirm
..\key\Scripts\python.exe -m vaultshare.cli admin recover --from-backup --confirm
```

### 密钥轮换

```powershell
..\key\Scripts\python.exe -m vaultshare.cli broker rotate
```

只新增密钥文件，旧钥保留；引用旧 `key_id` 的包继续可兑换。新包需重新执行
`broker info` 并核对新指纹。

### 修改密码

```powershell
python.exe -m vaultshare.cli admin passwd
```

修改成功后 `api_epoch` 递增，所有旧 Bearer token 立即失效。

### 排障

```powershell
python.exe -m vaultshare.cli admin status
```

显示 generation、包/授权/请求数量、当前代理密钥与代理健康状态。状态降级、
代理不可用、预留卡住、磁盘写失败、忘记凭证等场景见
[docs/SECURITY.md](docs/SECURITY.md) 的“异常恢复手册”。

### 登录页提示“页面已过期”/“浏览器没有发送会话 Cookie”

登录表单的 CSRF token 存在会话 Cookie 里。按提示区分原因：

- **没有发送会话 Cookie**：浏览器根本没带上 `vaultshare_session`。
  - 设置了 `VAULTSHARE_HTTPS=1` 却用 `http://` 访问时，带 `Secure` 的
    Cookie 不会被浏览器保存。改为通过反向代理的 `https://` 地址访问，或
    临时取消该变量并重启（启动信息会明确提示）。
  - 浏览器或插件禁止了本站 Cookie、使用了会丢弃 Cookie 的隐私模式。
- **页面已过期**：Cookie 存在但 token 不匹配，通常是页面打开太久、换过
  `secrets/flask_secret.key`、或服务端会话已失效。刷新登录页重新提交即可；
  失败后的页面会自动换发新 token，再点一次“登录”也能恢复。

服务端日志会输出 `login CSRF failed: cookie=present|missing`，可据此判断是
Cookie 缺失还是页面过期。

---

## 8. 测试

```powershell
# 在仓库根目录
python.exe -m unittest discover -s ff\tests

# 完整端到端（自行选择空闲端口，使用临时 VAULTSHARE_DATA）
python.exe ff\tools\e2e_check.py

# GUI 动作层全链路（不创建窗口，验证加密/上传/卡片/解密）
python.exe ff\tools\gui_flow_check.py

# 旧桌面应用回归（与本服务无关，验证删除分享模块后无回归）
python.exe -m unittest discover -s tests
```

覆盖范围包括：

- 规范化 JSON、签名域、HPKE 往返与独立参考实现交叉对测；
- 容器打包/解包、路径穿越、Windows 保留名与 ADS；
- 状态 MAC、journal 回放、压实、降级、备份不自动提升；
- 并发 8 线程 + 3 进程争抢 `max_uses=1`：恰好一次成功、`used == 1`；
- 同一 `request_id` 重放：字节一致、不重复扣减；
- 伪造/过期/错绑票据、预留不匹配、累计额度跨批次；
- Web 登录、TOTP 重放、锁定持久化、CSRF、Cookie 认证拒绝；
- 身份私钥口令错误与篡改检测；
- 子进程全链路验收（上传、两次兑换、重放、撤销、额度核对）。
- GUI 动作层验收：只加密 → 上传时生成策略 → 兑换解密，逐文件摘要一致；
  容器头部内嵌服务器地址可读，上传凭据不含明文 `K_pkg`（按本地交付方式上传，
  服务器不保存密文）。
- 本地交付：包可以签发口令并在没有密文的情况下兑换；`PUT /blob` 被拒、
  `GET /blob` 返回 404；客户端直接解密本地容器、不下载，容器错误在消耗次数
  前就被拦下（`tests/test_local_delivery.py`）。
- TLS 信任锚：`--ca-file` / `VAULTSHARE_CA_FILE` 只信任指定证书，另一张自签名
  证书与不指定时的系统根证书校验都会被拒（`tests/test_tls_pin.py`）。

已知跳过项：当前 Windows 环境不允许创建符号链接，相关测试标记为 skip。

---

## 9. 已知限制

- 代理是软件进程，**不是 TEE**；root/管理员可读密钥。
- 状态 MAC 密钥由 Web 与代理共享，只能检测外部篡改，不能证明 Web 诚实。
- 合法旧状态回滚无法检测；备份恢复是有意回滚。
- TOTP 密钥在凭证文件中明文（记事本可编辑的代价）。
- 单实例、本地磁盘；不支持多机共享状态。
- 网页上传默认关闭；开启后 Web 进程会短暂接触发送方私钥与 `K_pkg`
  （见 4.5 与 SECURITY.md §3.2）。网页仍不提供兑换。
- 桌面端是两个独立 GUI（需 PySide6），尚未随仓库提供已打包的 exe，接收方机器
  仍需 Python 环境或自行打包。
- 上传凭据 `upload-key.json` 只是密封的 `K_pkg`，上传时仍需发送方身份私钥与
  口令；不要把长期身份私钥复制到上传机器以外的地方。
- 包/口令备注是明文展示元数据（`data/notes.json`），不签名、不进 MAC；不要
  在备注里写口令、私钥密码等敏感内容。
- 容器头部的服务器地址与分享卡片都只是“减少输入”的提示，可被篡改；信任仍
  来自带外核对的发送方/代理指纹。
- HPKE 不使用 RFC 9180 的 `aad`，官方测试向量无法逐字节复现；偏差与替代验证
  见 [docs/PROTOCOL.md](docs/PROTOCOL.md) §4.2。
- 发送方身份撤销目前没有 CLI/Web 入口，需要人工操作（见 SECURITY.md）。

---

## 10. 文档

- [docs/PROTOCOL.md](docs/PROTOCOL.md)：线格式、签名、HPKE 上下文、IPC、容器、
  三阶段兑换状态机、版本演进。
- [docs/STATE.md](docs/STATE.md)：数据目录、状态信封、MAC、事务、journal、
  检查点、锁、崩溃矩阵、恢复。
- [docs/SECURITY.md](docs/SECURITY.md)：信任边界、代理不是 TEE、认证、密钥
  轮换、审计、部署建议、残余风险、密码学实现原则。
