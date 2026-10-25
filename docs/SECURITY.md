# 安全边界与运维手册

本文说明 VaultShare v1 的信任边界、已知残余风险、密钥轮换、审计与故障恢复。
凡本文与代码冲突，以代码为准并应尽快修正文档。

---

## 1. 安全目标

在本实现假设的威胁模型内：

- 未持有口令的第三方无法从服务器数据中恢复 `K_pkg` 或共享包明文；
- 未持有发送方私钥的人无法读出服务器上的明文口令；
- 未持有接收方临时私钥的人无法解开交付信封；
- 未通过认证（用户名 + 密码 + TOTP）的人无法使用管理 API；
- 状态文件被外部篡改、截断或损坏时，兑换停止而不是“重置后继续”；
- 网络重试、并发请求、进程崩溃不会导致超发、重复扣减或重复交付。

## 2. 非目标（明确不承诺）

- **不抵抗拥有服务器 root/管理员权限的攻击者。**
- **不是 TEE，也不是 HSM。** 进程隔离只是纵深防御。
- 不抵抗合法旧状态的整文件回滚（MAC 无法区分“旧但合法”与“当前”）。
- 不承诺绝对擦除内存中的密钥（`wipe` 只能尽力覆盖 Python 层副本）。
- 不承诺抵抗流量分析、拒绝服务或接收方主动导出明文。
- 不支持多机共享同一数据目录。

---

## 3. 信任边界

```
发送方（本地）                服务器主机                         接收方（本地）
┌──────────────┐   HTTPS   ┌──────────────────────────┐  HTTPS  ┌──────────────┐
│ 身份私钥      │──────────▶│ Flask Web 进程            │◀────────│ 临时 X25519   │
│ K_pkg（瞬时） │           │  state.json / 包密文      │         │ 口令           │
│ 明文目录      │           │  无 K_pkg、无 code_mac    │         │ 可信指纹       │
└──────────────┘           │        │ 回环 IPC + HMAC  │         └──────────────┘
                           │        ▼                  │
                           │ 密钥代理进程              │
                           │  代理私钥 / code_mac_key  │
                           │  只读状态并验 MAC         │
                           └──────────────────────────┘
```

- Web 与代理是两个进程。Web 只提交**已验证的请求**，接收**已封给接收方**的
  信封；默认配置下它不接触 `K_pkg` 明文或明文口令（网页上传为显式开启的
  例外，见 3.2）。
- 代理不信任 Web 的口头承诺：交付前自行读取 `state.json`、验证完整信封 MAC，
  并要求存在匹配的 `RESERVED` 记录。
- 接收方不信任服务器：所有签名材料都在本地重算与核对。
- 发送方不信任服务器返回的代理身份：打包前必须带外核对指纹。

### 3.1 独立软件代理 **不是** TEE

当前 `SoftwareKeyBroker` 是普通 Python 进程：

- 拥有主机 root/管理员权限的攻击者可以读取 `data/secrets/broker_keys/`、
  `code_mac.key`，或直接控制代理进程；
- 若 Web 与代理以同一 OS 用户运行，文件 ACL 无法阻止 Web 读取代理私钥；
- 进程隔离只保证“正常运行时 Web 代码路径拿不到私钥”。

因此本版本**不得**对外宣称能抵抗恶意服务器管理员。真正的隔离需要 TEE/HSM，
或至少为代理使用独立 OS 账号/容器并把密钥文件 ACL 限制给该账号。

状态 MAC 密钥由 Web 与代理共同持有：它能检测**没有密钥的外部篡改**，但
**不能证明状态来自诚实的 Web 进程**。恶意 Web 可以伪造一份 MAC 合法的状态，
代理无法区分。真正的独立额度仲裁需要代理自持计数器，这与“单一权威状态文件”
冲突，列为已知折衷。

### 3.2 网页上传：显式开启的边界例外

默认部署中，Web 进程永远不接触 `K_pkg` 明文或发送方私钥。设置
`VAULTSHARE_WEB_UPLOAD=1` 后，这条边界**被有意放宽**：

- 管理员通过网页表单上传 `sender.key` 与口令，Flask 进程在请求内解密身份私钥；
- Web 进程用发送方 X25519 私钥解开 `upload-key.json` 中的 `K_pkg`，并用它生成
  本次策略的 KeyConfig；服务器交付时还会完整验证容器；
- 代理生成口令后，Web 进程再用发送方私钥解开密封口令，在结果页显示一次。
- 包详情页的“增加口令”走同一信任边界：同样需要发送方 `.json` / `.key` 与
  私钥口令，Web 进程在请求内解密私钥并用它解封新口令，明文只在本次页面上
  显示一次；服务器会要求身份与创建该包时的发送方完全一致，并拒绝已撤销的包
  或超出已签名 `max_codes` / `max_total_redemptions` 的请求。
- 勾选“本地交付”时 Web 进程仍会接触私钥与 `K_pkg`，但**不接收也不保存容器**；
  浏览器仍会把表单里选中的文件发给 Web 进程，因此本地交付时不要选择
  `payload.vspk`。大文件应改用 CLI `--local-payload`，那条路径完全不会把密文
  传给服务器。

因此启用后，任何能读取 Web 进程内存、堆转储、调试器或 core dump 的人都能获得
`K_pkg` 与身份私钥，进而解密该包、签发新上传或解开该身份下的口令密文。这不是
“服务器慢慢学会解密”，而是一次明确的信任转移：**你选择让服务器代办发送方步骤**。

实现约束：

- 默认关闭；未设置时 `/upload` 只显示说明，POST 直接拒绝（HTTP 400）。
- 上传内容只写进 `tempfile.TemporaryDirectory()`，请求结束即删除；私钥临时文件
  落盘后立即收紧权限。
- 口令、私钥与 `K_pkg` 不写入日志、审计、状态或 Flask 会话；审计只记录
  `web_upload` / `web_grants_added` 事件（package_id、数量、操作者、IP）。
- 备注（包/口令）是明文展示元数据，存放在 `data/notes.json`，不进状态 MAC、
  不影响授权校验；页面会提示不要在其中写入敏感信息。
- 仍复用现有校验：上传凭据签名、身份绑定、容器完整解密（仅服务器交付）、
  Policy/KeyConfig 签名、代理当前密钥核对；不因为“来自网页”而跳过任何一步。
  本地交付无法验证容器，因为服务器根本没有拿到它；容器在加密时已由发送方
  完整验证。
- 页面不显示任何历史明文口令；明文只在本次结果页出现一次。
- 只应在完全由你掌控的主机、已启用 HTTPS（`VAULTSHARE_HTTPS=1`）时开启；否则
  继续使用 CLI 上传。

禁用该功能即可恢复原边界；已经上传的包不受影响。风险同时列入第 12 节。

---

## 4. 认证

### 4.1 三项登录

- 用户名 + 密码（Werkzeug scrypt 哈希）+ 6 位 TOTP，三项全部正确才成功。
- 所有失败返回同一句话（`用户名、密码或验证码错误`）；用户名错误时仍执行一次
  口令哈希校验，避免用响应时间枚举用户名。
- TOTP `valid_window = ±1` 步，并且时间步必须严格大于状态中的
  `auth.last_totp_step`，同一验证码重放被拒绝。
- TOTP 密钥在 `credentials.txt` 中是**明文**（记事本可编辑的直接代价）。能读
  该文件的人同时拥有密码哈希与 TOTP 密钥，因此它**不是**独立的第二因素，只是
  防止口令泄露后被直接使用。
- 登录失败按 `username|IP` 计数并持久化：前 4 次只记录，第 5 次起锁定，时长
  指数增长（60 秒起，上限 1 小时），重启不清零。

### 4.2 Web 会话与 CSRF

- 会话只把随机 `sid` 放进签名 Cookie（`HttpOnly`、`SameSite=Strict`、
  `VAULTSHARE_HTTPS=1` 时 `Secure`），服务端内存保存会话与 CSRF token。
- 登录成功轮换 `sid`（会话固定防护）；登出立即销毁；进程重启使全部会话失效。
- 所有 Web 写操作校验服务端 CSRF token；登录表单使用登录前的 `pre_csrf`。
- CSP 为 `script-src 'none'`，页面不含任何 JS，也不在浏览器接触密钥材料。
- 安全响应头：`nosniff`、`DENY`、`no-referrer`、`no-store`、HTTPS 时 HSTS。

### 4.3 API Bearer

- API 只接受 `Authorization: Bearer vs1.<payload>.<mac>`；带 Cookie 的请求即使
  同时有 Bearer 也直接拒绝（`cookie_auth`），避免浏览器把 API 当会话用。
- token 由 `flask_secret.key` 做 HMAC，负载含 `sub`、`iat`、`exp`、`jti` 与
  `epoch`；30 分钟过期。
- 修改密码（`admin passwd`）把 `auth.api_epoch` +1，所有旧 token 立即失效。
- 登录与兑换有进程内滑动窗口限速（每 IP 20 次/分、60 次/分）。**这不是安全
  边界**：重启清零、按进程计数，只挡最简单的暴力请求。

### 4.4 部署在反向代理之后

- 代码不信任 `X-Forwarded-For`，取 `request.remote_addr`。若前面有反向代理，
  所有客户端会共享代理 IP：登录锁定与限速按代理 IP 生效，审计里的 IP 也是代理。
  这是有意的保守选择；需要真实 IP 时请由代理做访问控制，而不是放宽代码。
- HTTPS 由反向代理终结时设置 `VAULTSHARE_HTTPS=1`，否则 Cookie 不带 `Secure`。
- **子路径部署**：两种方式任选其一。
  - 代理在 `location /vault/ { proxy_pass http://127.0.0.1:5000/; }` 中剥掉前缀，
    并转发 `X-Forwarded-Prefix: /vault`；`ProxyFix(x_prefix=1)` 会让 `url_for`、
    表单 action 与静态资源都带上 `/vault`。
  - 代理不发送该头时，设置 `VAULTSHARE_URL_PREFIX=/vault`。服务会在没有
    `SCRIPT_NAME` 时回退使用它，并把直接访问带来的 `/vault` 从 `PATH_INFO`
    剥掉；会话 Cookie 路径也限定到该前缀。
  - 不要只改 `APPLICATION_ROOT` 而不设置上述两项，否则页面里的链接不会带前缀。

---

## 5. 密钥管理

### 5.1 密钥清单

| 密钥 | 位置 | 谁能读 | 用途 |
| --- | --- | --- | --- |
| 代理 X25519 私钥 | `secrets/broker_keys/<id>.hpke.key` | 代理 | 解 KeyConfig、解兑换请求 |
| 代理 Ed25519 私钥 | `secrets/broker_keys/<id>.ed25519.key` | 代理 | 签票据与回执 |
| `code_mac.key` | `secrets/code_mac.key` | 仅代理 | 口令验证值 |
| `state_mac.key` | `secrets/state_mac.key` | Web + 代理 | 状态完整性 |
| `ipc_hmac.key` | `secrets/ipc_hmac.key` | Web + 代理 | IPC 消息认证 |
| `flask_secret.key` | `secrets/flask_secret.key` | Web | 会话与 Bearer 签名 |
| TOTP 密钥 | `secrets/credentials.txt`（明文） | 读文件者 | 登录 |
| 发送方私钥 | 客户端本地 `sender.key` | 发送方 | 签名、解口令密文 |

- 生成使用 `os.urandom` + `O_CREAT|O_EXCL`；Windows 显式 `O_BINARY`，避免
  0x0A/0x1A 被文本模式改写。
- 代理私钥不进入环境变量、Flask 配置、日志、审计或状态文件。
- 权限：POSIX 0600/0700；Windows `icacls /inheritance:r` 只授权当前用户。
  失败必须告警。

### 5.2 代理密钥轮换

```
vaultshare broker rotate
```

- 生成新的 `key_id` 与两把密钥（只新增文件，不删除旧文件）；
- 更新 `state.body.broker.current_key_id`；
- 审计 `key_rotated`。

旧密钥必须保留，直到所有引用它的包过期或撤销：KeyConfig 记录 `broker.key_id`，
代理按包选择解密密钥。删除旧密钥前请确认没有活动包。

轮换后：

1. 发送方重新执行 `broker info --server ... --out ...` 并带外核对新指纹；
2. 新包使用新密钥；旧包继续用旧密钥兑换，回执由旧密钥签名；
3. 接收方从 KeyConfig/公开材料取得该包的代理公钥与指纹，不依赖“当前密钥”。

新包创建时服务器会核对 KeyConfig 使用的 `key_id` 与在线代理当前密钥一致；
不一致返回 `broker_key_changed`。

### 5.3 发送方身份轮换

- `identity init` 生成新身份，`identity register` 注册。旧身份继续服务旧包。
- 旧 X25519 私钥必须保留到所有旧口令密文过期，否则已签发口令无法解开。
- 同一 `sender_key_id` 不允许静默更换内容（`identity_conflict`）。
- 当前版本**没有** CLI/Web 的身份撤销入口；撤销需要停止服务后按 `STATE.md`
  手工修改状态并重算 MAC，属于高风险操作。若需要常规轮换与撤销，应在后续
  版本补充受审计的管理命令，而不是手工改状态文件。

### 5.4 口令与 `K_pkg`

- `K_pkg` 每个包随机 32 字节，只在发送方打包、代理交付时短暂存在；容器密钥由
  HKDF 派生。
- 明文口令只在代理内存中存在，立即密封给发送方；服务器只保存 HMAC 验证值。
- 例外：启用网页上传（第 3.2 节）时，Web 进程会短暂持有 `K_pkg` 与发送方私钥，
  并在请求内解封口令；默认关闭。
- 内存清除是尽力而为，不能保证解释器/密码库内部副本全部消失。

---

## 6. 本地 IPC 进程认证

- 只绑定回环地址，启动时强制检查；不支持远程代理。
- 每条请求带 `v/seq/ts/request_id/body_sha256/op/body/mac`，MAC 为
  `HMAC-SHA256(ipc_hmac_key, canonical(具名对象))`；时间戳 ±60 秒。
- 响应同样带 MAC，客户端验签后才使用。
- 重放缓存键为 `(request_id, body_sha256, op)`，TTL 600 秒；同 `request_id`
  不同内容一律拒绝。
- 创建口令、预授权票据与交付信封都有持久幂等记录；代理重启后仍然有效。
- `ipc_hmac.key` 被 Web 与代理共享。能读该文件的本地攻击者可以伪造 IPC，但
  仍需要代理调用其密码学操作；它不是 TEE 边界的一部分。

---

## 7. 状态完整性与回滚

- MAC 覆盖完整信封（`format`、`version`、`generation`、`body`）。
- 外部改写会导致 MAC 失败 → 降级，兑换返回 503，不重置授权。
- journal 条目同样带完整信封与 MAC；generation 不连续或同代不同内容 → 降级。
- **合法旧状态的整文件回滚无法检测**：持有状态文件与 MAC 密钥的人可以把
  `state.json` 换成旧副本，MAC 仍然正确。这是已接受的残余风险。
- 恶意 Web 可以伪造合法状态交给代理；见 §3.1 的 MAC 共享限制。
- 因此：**数据目录的写权限必须视为“完全控制额度系统”的能力**。备份、快照、
  容器镜像中都不应包含未受保护的 `data/`。

---

## 8. 审计

`data/audit.jsonl` 追加写并在每条后 `fsync`。写入失败会打印到 stderr——审计
不可写本身是必须让人看见的故障，但不会让业务“假装成功”。

实际事件（以代码为准）：

| 事件 | 触发 |
| --- | --- |
| `login_ok` / `login_fail` | 登录成功/失败（失败含原因与失败次数） |
| `login_session` / `logout` | Web 会话建立/登出 |
| `state_initialized` / `state_recovered` / `state_corrupt` | 状态生命周期 |
| `disk_error` | 备份/写入失败 |
| `identity_registered` | 发送方身份注册 |
| `package_created` / `payload_uploaded` | 创建包、上传容器 |
| `grants_created` | 创建口令（服务端与代理各记一条） |
| `codes_read` | 读取密封口令 |
| `web_upload` | 网页上传完成（包 ID、口令数、操作者、IP、是否新建） |
| `web_grants_added` | 网页增加口令（包 ID、数量、操作者、IP） |
| `package_note_updated` | 包备注修改（包 ID、操作者） |
| `grant_notes_updated` | 口令备注批量修改（包 ID、操作者） |
| `package_revoked` / `grant_revoked` | 撤销 |
| `redeem_delivered` / `redeem_denied` | 兑换交付/拒绝（代理记录拒绝原因） |
| `broker_unavailable` | Web 调用代理失败 |
| `key_rotated` | 代理密钥轮换 |
| `password_changed` | 修改登录密码 |

不记录：口令明文、`K_pkg`、私钥、TOTP 密钥、Bearer token、`code_verifier`。
`AuditLog` 对已知敏感字段名做 `[redacted]`，但调用方仍不得传入密文正文。

登录锁定的具体动作记录为 `login_fail` 的 `locked` 字段，而不是单独事件。

---

## 9. 异常恢复手册

### 9.1 兑换返回 503

按顺序检查：

1. `vaultshare admin status` → 状态是否降级、代理健康是否可用；
2. 代理进程是否在运行（`broker.lock`、`VAULT...` 端口）；
3. `data/audit.jsonl` 最近事件（`broker_unavailable`、`state_corrupt`、
   `disk_error`）；
4. 磁盘空间与文件权限。

### 9.2 状态损坏 / 降级

- 不要删除 `state.json`，不要手工编辑 MAC，不要“重新初始化”。
- 先 `vaultshare admin backup` 备份现场；
- 若主状态可解析、只是 journal 领先：停止服务后
  `admin recover --from-journal --confirm`；
- 若主状态已损坏：检查 `state.json.bak` 是否合法，使用
  `admin recover --from-backup --confirm`（会归档当前 journal）；
- 恢复后核对包、grant 与 `used`，并审计 `state_recovered`。

从备份恢复是有意回滚：备份之后的兑换记录会消失，但已交付给接收方的 `K_pkg`
不会因此失效。必要时立即撤销相关包/口令。

### 9.3 预留已提交但交付失败（`reservation_stuck`）

- 额度已占用且永不回滚；这是设计选择，防止“失败即免费”。
- 用同一 `request_id` 重试通常可以完成交付（代理会重新预授权并要求匹配的
  `RESERVED` 记录）。
- 若口令在此期间被撤销，代理拒绝交付，预留保持原状；由管理员决定是否人工
  处理该请求记录。不要直接删除 `requests` 条目来“释放额度”，那会破坏审计与
  幂等。

### 9.4 代理不可用

- Web 的上传、发码、兑换都依赖代理；Web 本身仍可登录查看状态。
- 代理启动时会检查 `broker.lock`；两个代理不能同时运行。
- 若状态引用的代理密钥文件缺失且已有包，服务会拒绝启动
  （`broker_key_missing`），以避免静默换钥让旧包无法兑换。恢复密钥文件，或
  在确认没有活动包后人工轮换。

### 9.5 首次凭证文件未删除

非交互启动时凭证写入 `data/secrets/INITIAL_CREDENTIALS.txt`，登录页会显示
告警。读取后运行：

```
vaultshare admin ack-init
```

程序会尽力覆写后删除。该文件包含明文密码与 TOTP 密钥，不应备份或进入镜像。

### 9.6 忘记密码 / 丢失 TOTP

`admin passwd` 需要当前密码；两条都丢失时，只能由管理员在可信环境下按
`credentials.txt` 的 INI 结构重建账号（写入新的 scrypt 哈希与新的 TOTP 密钥），
并提高 `auth.api_epoch` 使旧 token 失效。此过程必须停止服务、备份现场并审计。

### 9.7 时钟

- IPC 时间戳允许 ±60 秒；代理与 Web 同机部署，通常没有偏差。
- 兑换请求 `created_at` 允许 ±600 秒；票据有效期 120 秒。
- 接收方本机时钟偏差过大会被拒绝，这不是服务器故障。

---

## 10. 部署建议

必须：

1. **代理与 Web 使用不同 OS 账号或不同容器**，数据目录 ACL 只授予各自需要
   的文件；至少不要让 Web 账号能读 `broker_keys/` 与 `code_mac.key`。
2. **只允许一个 Web 实例与一个代理实例**（`writer.lock` / `broker.lock`）。
3. **数据目录放在本地磁盘**；不支持 NFS/SMB 共享。
4. 使用反向代理终结 TLS，并设置 `VAULTSHARE_HTTPS=1`；不要直接暴露 Flask
   开发服务器。
5. 只对必要来源开放 Web 端口；代理端口只绑定回环。
6. 备份 `data/` 时按敏感数据对待；备份中不包含明文口令，但包含 TOTP 密钥与
   状态（含已签名的信封缓存）。
7. 不要开启 Flask debug、不要把 `data/` 放进静态目录、不要在日志里打印请求
   体。
8. 除非确实需要网页上传，否则保持 `VAULTSHARE_WEB_UPLOAD=0`；开启时确保
   Web 进程运行在受限账号下，并限制 core dump / 调试器访问。
9. 自签名部署时，客户端用 `--ca-file` 或 `VAULTSHARE_CA_FILE` 指定唯一信任的
   PEM 证书。设置后只加载该文件、不加载系统根证书，因此换证书必须同时更新
   所有客户端；证书 SAN 必须覆盖实际访问的 IP/主机名。不要为了省事关闭校验
   （客户端没有 `--insecure`，也不应该添加）。

建议：

- 用独立磁盘或目录配额限制 `data/`，避免 DoS 写满根分区；
- 定期运行 `vaultshare admin backup` 并把备份离线保存；
- 定期检查 `audit.jsonl` 中的 `login_fail`、`redeem_denied`、`state_corrupt`；
- 轮换代理密钥时先确认没有活动包依赖旧钥；
- 对发送方身份采用带外核对的指纹（TOFU），不要只信服务器页面。

---

## 11. 安全测试映射

| 风险 | 测试 |
| --- | --- |
| 错误口令/TOTP、用户枚举、锁定持久化 | `tests/test_web.py` |
| TOTP 重放 | `tests/test_web.py`（`验证码已使用`） |
| CSRF、Cookie 认证绕过 | `tests/test_web.py` |
| Bearer 与 API epoch 失效 | `tests/test_web.py` |
| IPC MAC/时间戳/重放/同 ID 不同内容 | `tests/test_ipc.py` |
| 并发兑换恰好一次、重试字节一致 | `tests/test_redeem.py` |
| 伪造/过期/错绑票据、预留不匹配 | `tests/test_redeem.py` |
| 累计额度跨批次不可绕过 | `tests/test_redeem.py`、`test_primitives.py` |
| 状态 MAC/回放/压实/降级/不自动提升备份 | `tests/test_state.py` |
| 第二写者（跨进程）互斥 | `tests/test_state.py` |
| 容器篡改、路径穿越、Windows 路径规则 | `tests/test_container.py` |
| 指纹核对可选但给出即须匹配、其余验证不降级 | `tests/test_redeem_fingerprint.py` |
| 本地交付不接收密文、blob 拒绝/404、错误容器不耗额度 | `tests/test_local_delivery.py` |
| 身份私钥加密与篡改检测 | `tests/test_identity.py` |
| HPKE 套件参数与 key schedule | `tests/test_hpke_reference.py` |
| 全链路（含重放、撤销、额度） | `tests/test_e2e.py` |
| 网页上传默认关闭、口令不进日志/状态、重复上传幂等 | `tests/test_web_ui.py` |
| 网页增加口令：身份不符/包已撤销/超出策略上限/开关关闭均拒绝 | `tests/test_web_ui.py` |
| 备注长度限制、保存/清空、与状态及授权校验隔离 | `tests/test_web_ui.py` |
| 子路径部署（X-Forwarded-Prefix 与 `VAULTSHARE_URL_PREFIX`） | `tests/test_web_ui.py` |

运行：

```
.\key\Scripts\python.exe -m unittest discover -s ff\tests
```

---

## 12. 残余风险清单

1. **软件代理不是 TEE**：管理员/root 可读密钥或控制进程。
2. **状态 MAC 密钥共享**：不能证明状态来自诚实 Web；恶意 Web 可伪造额度。
3. **合法旧状态回滚不可检测**。
4. **TOTP 密钥明文**：能读 `credentials.txt` 的人同时拥有密码哈希与 TOTP。
5. **Windows ACL 限于用户级**：同一用户运行的任意进程都能读取密钥文件。
6. **审计不可防篡改**：本地攻击者可删除或改写 `audit.jsonl`；未做远程日志。
7. **内存擦除尽力而为**：解释器/库内部副本可能残留。
8. **无进程级沙箱**：Web 与代理共享同一主机与文件系统命名空间（除非另行容器化）。
9. **限速为进程内**：重启清零，按进程计数，不是抗 DoS 边界。
10. **未处理的密钥轮换自动化**：旧密钥清理需要人工确认；发送方身份撤销没有
    CLI 入口。
11. **HPKE 与 RFC 9180 不完全兼容**：上下文绑定放在 `info`，不使用 `aad`；
    官方向量无法逐字节复现（详见 `PROTOCOL.md` §4.2）。
12. **无硬件密钥/远程证明**：发送方与接收方之间的信任锚是指纹 TOFU，首次使用
    必须带外核对。
13. **容器/卡片里的服务器地址只是提示**：它可被篡改或指向攻击者的服务器。
    真正阻止替换的是发送方/代理指纹核对；只打开容器而不核对指纹，等于对
    容器里的地址做盲目信任。
13a. **“要求核对指纹”标记只是发送方偏好**：容器头部 v3 的
    `require_sender_fingerprint` 决定解密工具是否显示并强制指纹输入。它受 AAD
    保护，但取得 `K_pkg` 前无法认证；能替换整个容器的攻击者也能把它改成 0。
    因此取消勾选会让接收方失去对服务器冒充发送方的防护，只应在完全可信的
    渠道/部署中使用；文档和界面都不把它描述为密码学保证。
14. **附带口令的分享卡片就是凭证**：卡片文件一旦泄露，持有者在额度内即可
    兑换。界面默认不写入口令，写入时按敏感文件保管。
15. **上传凭据仍需长期身份**：`upload-key.json` 只含密封的 `K_pkg`，单独泄露
    不能解密；但上传步骤需要发送方身份私钥与口令来解封并签名策略。把身份文件
    复制到不可信机器，会让该机器能在额度允许范围内完成上传并接触 `K_pkg`。
16. **网页上传改变信任边界**（仅 `VAULTSHARE_WEB_UPLOAD=1`）：服务器代办发送方
    步骤，会短时持有身份私钥、`K_pkg` 与明文口令；管理员失守或内存转储泄露时
    这些材料随之泄露。默认关闭，开启即表示接受该风险。勾选“本地交付”能避免
    密文经服务器，但不会改变这条密钥边界，也不会阻止浏览器把已选中的文件
    发送给 Web 进程。
17. **本地交付（`payload_mode=local`）把密文交给发送方自己分发**：服务器只存
    元数据与口令，因此不再有服务器端的密文可用性/完整性副本。发送方给出的
    容器若在传输中损坏，接收方会因容器头部或解密认证失败而无法解包；本地
    交付的包没有服务器声明的 SHA-256 可比对，容器选中错误时只能依靠头部
    `package_id` 被发现。容器完整性仍由 secretstream 认证标签保证，攻击者无法
    在不知道 `K_pkg` 时伪造内容；但“发送方给的这份文件是否就是当初加密的
    文件”需要发送方通过可信渠道自行确认（例如另行公布摘要）。
18. **本地交付不改变服务器可见性、但改变可用性预期**：服务器没有密文可撤回
    或重新下发，撤销包/口令只阻止新的兑换请求，不能收回接收方手里的容器。

---

## 13. 密码学实现原则

- 只使用 `cryptography`、PyNaCl、Werkzeug 提供的原语；**不自行设计或实现加密
  算法**。
- HPKE 的“上下文放进 `info`”是基于库 API 事实的限制，不是自创密码学；其认证
  性质与偏差已在 `PROTOCOL.md` 明确记录，并用独立实现交叉验证套件参数。
- 所有签名/MAC/摘要只对规范化 JSON 计算；域标签分离对象类型。
- 失败一律拒绝，不做“尽量修复”；状态损坏停止兑换，不自动重置授权。
