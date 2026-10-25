# 状态、锁与崩溃恢复

本文描述 `ff/data/` 的落盘格式与恢复语义。所有写入路径都集中在这几个模块：

- `vaultshare/storage/state.py`：权威状态、journal、检查点、降级与恢复
- `vaultshare/storage/atomic.py`：原子写与原子替换
- `vaultshare/storage/locking.py`：跨进程文件锁
- `vaultshare/storage/package_store.py`：包目录与上传提交
- `vaultshare/storage/audit.py`：追加式审计

---

## 1. 数据目录

```
data/
  packages/<package_id>/
    keyconfig.json        发送方签名的 canonical JSON 字节
    policy.json           发送方签名的 SharePolicy
    payload.vspk          加密容器
    meta.json             上传摘要（不作为信任来源）
  notes.json              包/口令备注（明文、纯展示，不进 MAC、不参与校验）
  state.json              权威状态（带 MAC）
  state.json.bak          上一代状态（原子写，合法时才存在）
  state.journal.jsonl     已提交事务的完整信封，每行一条
  journal.checkpoint.json 最近两个检查点
  audit.jsonl             追加式审计
  locks/
    writer.lock           服务进程生命周期独占
    broker.lock           代理进程生命周期独占
    state.lock            每次状态事务（含启动）独占
  broker/
    idempotency.json      跨重启幂等记录
    envelopes/<request_id>.json  已签名信封缓存
  backups/                人工备份、恢复时归档的 journal
  secrets/
    credentials.txt       账号（scrypt 哈希）、TOTP 密钥（明文）
    INITIAL_CREDENTIALS.txt  一次性初始凭证
    state_mac.key         Web 与代理共读
    ipc_hmac.key          Web 与代理共读
    code_mac.key          仅代理读取
    flask_secret.key      Web 会话签名
    broker_keys/<key_id>.hpke.key
    broker_keys/<key_id>.ed25519.key
```

`settings` 只从环境变量读取（`VAULTSHARE_DATA` 等），不把密钥放进 Flask 配置。

`notes.json` 由 `NoteStore` 单独加锁、原子写（结构为
`{"packages": {"<pid>": "..."}, "grants": {"<gid>": "..."}}`）。它**刻意不放进
`state.json`**：备注是纯展示元数据，而 `state.json` / grant 记录采用严格字段集
校验，代理在兑换时也会重新校验整个状态信封与 grant；把可变文本混进去会让
“改备注”看起来像一次授权变更。因此备注被篡改或损坏最多影响显示（损坏时按空
备注处理并告警），不影响任何签名、额度或兑换状态，也不随 `state.json` 的 MAC
与 journal 一起回放。单条备注最多 500 字符（去首尾空白、统一换行、去掉除
`\n`/`\t` 外的控制字符）。

---

## 2. `state.json` 信封

```json
{
  "format": "vaultshare-state",
  "version": 1,
  "generation": 42,
  "body": {
    "senders": {},
    "packages": {},
    "grants": {},
    "requests": {},
    "revoked_packages": {},
    "auth": {"last_totp_step": 0, "lockouts": {}, "api_epoch": 1},
    "grants_counters": {},
    "broker": {"current_key_id": ""}
  },
  "mac": "<64 hex>"
}
```

`body` 的键集合必须**精确等于**上述 8 个键（`REQUIRED_BODY_KEYS`），缺一或多
一都进入降级模式。

### 2.1 MAC

```
mac = HMAC-SHA256(state_mac_key, canonical({
    "format": ..., "version": ..., "generation": ..., "body": ...
}))
```

MAC 覆盖**完整信封**，不只是 `body`。只 MAC `body` 会让 `version` 或
`generation` 被替换而无法察觉。journal 条目保存并认证的是同一个完整信封。

`state_digest`（预授权票据里）定义为 `SHA256(canonical(完整信封，含 mac))`，
与 MAC 不是同一概念：前者用于“快照是否变化”，后者用于“内容是否被外部篡改”。

### 2.2 `senders`

```json
{
  "<sender_key_id>": {
    "sender_key_id": "...",
    "identity_hash": "<64 hex>",
    "ed25519_public_key": "<b64url32>",
    "x25519_public_key": "<b64url32>",
    "registered_at": 0,
    "revoked": false,
    "record": { ...完整自我签名身份记录... }
  }
}
```

同一 `sender_key_id` 不得被不同内容静默覆盖（返回 `identity_conflict`）。

### 2.3 `packages`

```json
{
  "<package_id>": {
    "status": "active",
    "created_at": 0,
    "keyconfig_sha256": "<64 hex>",
    "policy_sha256": "<64 hex>",
    "payload_sha256": "<64 hex>",
    "payload_size": 0,
    "payload_mode": "server",
    "broker_key_id": "<32 hex>",
    "sender_key_id": "<32 hex>",
    "sender_identity_hash": "<64 hex>"
  }
}
```

状态中的摘要才是信任来源；`meta.json` 只是辅助信息。代理与服务器每次使用包
时都会重算文件摘要并比对。

`payload_mode` 取 `server`（默认，密文上传到服务器）或 `local`（服务器只保存
元数据与口令，不接收密文，`payload_sha256`/`payload_size` 保持为空/0）。
`local` 包不写入 `payload.vspk`，`require_payload` 检查会跳过它；`server` 包
一旦缺少 `payload_sha256` 仍按“尚未上传”拒绝签发与兑换。旧状态没有该字段时
一律按 `server` 处理。

### 2.4 `grants`

```json
{
  "<grant_id>": {
    "grant_id": "...", "package_id": "...",
    "code_verifier": "<64 hex>",
    "sealed_code": {"enc": "...", "ciphertext": "..."},
    "expires_at": 0, "max_uses": 1, "used": 0,
    "revoked": false, "policy_version": 1,
    "batch_id": "<32 hex>", "created_at": 0
  }
}
```

### 2.5 `requests`

```json
{
  "<request_id>": {
    "package_id": "...",
    "grant_id": "...",
    "recipient_pk_hash": "<64 hex>",
    "status": "RESERVED | DELIVERED | DENIED",
    "authorization_id": "<32 hex> | null",
    "reservation_id": "<32 hex> | null",
    "state_generation": 0,
    "reserved_at": 0,
    "delivered_at": 0,
    "opaque_request": "<base64url(canonical(outer))>",
    "ticket": { ...代理预授权票据... },
    "envelope_core": { ... } | null,
    "receipt": { ... } | null
  }
}
```

- 以全局唯一 256-bit `request_id` 为键，天然满足 `(grant_id, request_id)` 幂等。
- `opaque_request` 绑定外层请求内容；同一 `request_id` 携带不同内容返回
  `request_id_reuse`，不会解锁或改写已有记录。
- `authorization_id` / `reservation_id` / `state_generation` 把票据与已提交
  预留绑定，代理交付前逐项核对。

### 2.6 其余

- `revoked_packages`：`{package_id: revoked_at}`，与 `packages.status` 同时维护。
- `auth`：`last_totp_step`（严格递增防重放）、`lockouts`（持久化登录锁）、
  `api_epoch`（修改密码时 +1，使全部 Bearer token 失效）。
- `grants_counters`：每包 `{issued, allocated_uses, used}`。只作为摘要/展示；
  权威校验从 `grants` 重新计算（`grant_metrics`），防止计数器被单独篡改后
  绕过额度。
- `broker.current_key_id`：当前代理密钥。包记录各自的 `broker_key_id`，轮换后
  旧包继续用旧钥。

---

## 3. 事务

`StateStore.transaction(mutator)` 的固定顺序：

1. 获取进程内 `RLock`；
2. 获取跨进程 `locks/state.lock`（超时 20 秒）；
3. **重新读盘**并验证 MAC。绝不信任可能被外部替换的内存副本；
4. 检查 generation 单调性：比内存小 → 降级（`generation 倒退`）；同代但内容
   不同 → 降级；
5. 深拷贝 `body`，以 `generation + 1` 调用 `mutator`。`mutator` 抛异常则整个
   事务放弃，**不产生任何落盘副作用**；
6. 构造新信封并计算 MAC；
7. 提交（`_commit`）：
   1. 同目录 `mkstemp` 写完整 JSON，`flush` + `fsync`；
   2. 追加一行 canonical 信封到 `state.journal.jsonl` 并 `fsync`；
   3. 把旧 `state.json` 原子复制为 `state.json.bak`（失败只写审计，不阻止）；
   4. 原子替换 `tmp → state.json`（Windows 走 `MoveFileExW(REPLACE_EXISTING |
      WRITE_THROUGH)`，瞬时占用有限重试）；
   5. `fsync` 目录（POSIX；Windows 尽力而为）；
   6. 读回并逐字节比对，不一致抛 `OSError`（“状态替换后读回校验失败”）；
8. 更新内存信封，写检查点；
9. 必要时压实 journal。

`used` 只在第 7 步成功后才被认为已提交；额度一经占用永不回滚。

失败注入测试确认：`replace_file` 失败时主状态保持旧代，但 journal 已包含新代，
重启回放后得到新状态（`test_failure_after_journal_append_recovers_on_restart`）。

---

## 4. journal、检查点与压实

### 4.1 journal 条目

每行一个完整信封（含 `format/version/generation/body/mac`），canonical JSON +
换行。条目只有在“写入并 fsync”后才可能被回放；最后一行若因崩溃而截断
（文件不以换行结尾），整行忽略，不视为损坏。

### 4.2 检查点

每次状态替换成功后写 `journal.checkpoint.json`：

```json
{
  "format": "vaultshare-journal-checkpoint",
  "version": 1,
  "checkpoints": [
    {"generation": 42, "state_sha256": "<64 hex>", "at": 1234567890}
  ]
}
```

只保留最近 2 个，用于人工核对与恢复参考。

### 4.3 压实

当 journal 超过 **256 条**或 **8 MiB** 时，在持有状态锁的情况下：

1. 读取并逐条验证 journal；
2. 只保留 `generation > 当前已提交代` 的条目（正常运行时应为空）；
3. 写入同目录临时文件 + `fsync` + 原子替换 + `fsync` 目录；
4. 重写检查点。

实现方式是“以当前 `state.json` 为检查点重写 journal”，不是逐条删除已确认条目；
这样不会出现“删到一半崩溃”的中间态。

### 4.4 generation 不变量

- 主状态与 journal 的 generation 必须单调不减。
- 回放时要求 `journal.generation == current.generation + 1`，不连续 → 降级。
- 同 generation 内容不同 → 降级。
- 无法判定哪些条目已提交（例如主状态损坏或 journal 中间行损坏）→ 降级，
  禁止兑换，要求人工恢复。

---

## 5. 启动流程

`StateStore.startup()` **在整个启动过程持有 `state.lock`**。原因：启动会清理
`*.tmp`，若与另一个进程的原子写并发，可能删掉对方正在写入的临时文件。生产
环境本应只有一个写者，但误启动的第二实例不应损坏状态。

持有锁后：

1. 清理 `data/` 下遗留的 `.*.tmp`；
2. 主状态不存在：
   - 若存在非空 journal → 降级（`主状态文件缺失，但存在未回放的 journal`）；
   - 否则若存在 `.bak` → 降级（`存在 .bak 但不自动提升`）；
   - 否则初始化为 generation 0；
3. 解析主状态并验证 MAC；损坏 → 降级；
4. 回放 journal：逐条验证完整信封 MAC、generation 连续性与同代内容一致性；
5. 若回放得到更高代：原子写入主状态，审计 `state_recovered`；
6. 写检查点，必要时压实。

**绝不自动提升 `.bak`，绝不重置任何授权。** 自动提升会让一次外部替换伪装成
“正常回滚”。

---

## 6. 降级模式

进入降级的条件：

- 主状态不是合法 UTF-8 JSON、格式/版本/MAC/结构校验失败；
- 主状态缺失但存在 journal 或 `.bak`；
- journal 损坏（非末尾半行）、generation 不连续；
- 事务读盘时发现 generation 倒退或同代不同内容。

降级后的行为：

- `StateStore.transaction` 抛 `CorruptState`，所有需要写状态的操作失败；
- `/api/v1/redeem` 返回 503（`state_corrupt`）；
- 登录等写状态的操作同样失败（保守）；
- 审计写 `state_corrupt`，健康检查返回 `degraded` 与原因；
- **不重置 grant、不恢复额度、不删除 journal。**

---

## 7. 人工恢复

恢复只能显式执行，且必须先停止服务（`writer.lock` 被占用则拒绝）：

```
vaultshare admin recover --from-journal --confirm
vaultshare admin recover --from-backup  --confirm
vaultshare admin backup
```

### `--from-journal`

- 以**当前主状态**为基准，回放 journal 中更高代且验证通过的条目；
- 要求主状态本身可解析且 MAC 有效。主状态已损坏时该命令会失败，应改用
  `--from-backup`。
- 恢复后压实 journal 并写检查点。

### `--from-backup`

- 读取并验证 `state.json.bak`（同样要求完整 MAC 与结构合法）；
- 先把现有 journal **归档**到 `backups/journal-backup-recovery-<ts>.jsonl`
  再清空。否则下次启动会把“被放弃的未来”重新回放，等于恢复失败；
- 写入备份状态，审计 `state_recovered(source=backup)`。

注意：从备份恢复是一种有意的回滚。备份比 journal 旧时，其间已提交的兑换记录
会消失，但这不会恢复已经交给接收方的 `K_pkg`。恢复后必须人工核对包与授权
状态。

### 备份

`vaultshare admin backup` 复制 `state.json`、`.bak`、journal、检查点、审计与
`credentials.txt` 到 `data/backups/<UTC 时间戳>/` 并收紧权限。备份**包含**
TOTP 密钥与状态，按敏感文件保管。恢复不是自动的。

---

## 8. 锁

| 锁 | 持有者 | 时机 |
| --- | --- | --- |
| `locks/writer.lock` | Web 服务进程 | 启动时获取，退出时释放；第二个服务进程拿不到就拒绝启动 |
| `locks/broker.lock` | 代理进程 | 同上；第二个代理拒绝启动 |
| `locks/state.lock` | 任意状态读者/写者 | 启动全程、每次事务、人工恢复 |

实现：

- POSIX：`fcntl.flock(LOCK_EX | LOCK_NB)`，轮询超时。
- Windows：`msvcrt.locking(LK_NBLCK, 1)`。文件初始化后与每次加锁前都把文件
  位置 `lseek` 到 0——`msvcrt` 从**当前文件位置**开始锁，写入哨兵字节后不
  归零会让两个进程锁到不同字节，互斥形同虚设（已回归测试覆盖）。
- 只支持本地磁盘。NFS/SMB 上的咨询锁不保证互斥，**不支持**多机共享数据目录。
- Windows 的字节锁属于进程：同一进程内的第二个句柄不会冲突，因此“第二写者”
  测试必须用子进程。

代理读取状态时只做“读文件 + 验 MAC”，不获取 `state.lock`（它不能阻塞服务
写入）；它要求读到的是某个已提交的完整信封，并通过 `RESERVED` 记录核对。

---

## 9. 崩溃与磁盘故障矩阵

| 故障点 | 结果 |
| --- | --- |
| 写 tmp 时崩溃 | 主状态与 journal 未变；启动清理 tmp |
| journal fsync 前崩溃 | 无该事务；主状态旧代 |
| journal fsync 后、替换前崩溃 | 重启回放得到新事务；`used` 不丢 |
| 替换后、目录 fsync 前崩溃（POSIX） | 可能丢目录项更新；journal 仍可回放 |
| 读回校验失败 | 事务抛错；journal 已含新代，重启回放完成 |
| 磁盘满写 journal 失败 | 事务失败，无状态变更 |
| 磁盘满写 `.bak` 失败 | 仅审计 `disk_error`，主流程继续 |
| 主状态被外部截断/改写 | MAC/解析失败 → 降级；禁止兑换 |
| 合法旧状态被恢复（回滚） | MAC 无法检测；见 SECURITY.md 残余风险 |
| 两个进程同时启动 | `state.lock` 串行化启动；`writer.lock` 阻止两个写者 |

---

## 10. 代理侧持久化

### `data/broker/idempotency.json`

```json
{
  "format": "vaultshare-broker-idempotency",
  "version": 1,
  "entries": {
    "grants:<batch_id>": {"expires_at": 0, "value": {...}},
    "authorize:<request_id>:<body_sha256>": {"expires_at": 0, "value": {"ticket": {}}}
  }
}
```

- 原子写、权限收紧、上限 20000 条（按过期时间淘汰）。
- 文件损坏视为代理不可用（`Unavailable`），**不**清空缓存继续跑；否则一次
  重试可能重复发码。

### `data/broker/envelopes/<request_id>.json`

- 只含已签名的 `envelope`，不含 `K_pkg`；
- 记录 `body_sha256`；同 `request_id` 不同请求内容一律拒绝；
- 读失败视为缓存缺失；内容摘要不一致是硬错误。

---

## 11. 权限

- POSIX：目录 0700、文件 0600。
- Windows：`icacls <path> /inheritance:r /grant:r "<DOMAIN\\USER>:(OI)(CI)F"`
  （目录）或 `"<USER>:F"`（文件）。
- 收紧失败必须打印警告；调用方可见 `False`。
- 重要限制：Windows 上“只授予当前用户”仍然允许**该用户运行的任何进程**读取。
  这不是进程隔离的替代品，见 SECURITY.md。

---

## 12. 测试

`ff/tests/test_state.py` 覆盖：

- 初始化 generation 0 与检查点；
- 事务代数、journal 行、重新加载；
- mutator 抛异常无副作用；
- journal 回放（替换前崩溃）；
- journal gap → 降级；
- 末尾半行忽略；
- 压实（条目阈值）与检查点；
- 主状态损坏 → 降级且不提升 `.bak`；
- 主状态缺失 + journal / 仅有 `.bak` 的降级原因；
- 人工备份恢复与 journal 归档；
- generation 倒退、同代不同内容降级；
- 不同 MAC 密钥拒绝；
- journal 写后写主状态失败，重启恢复；
- 第二个**进程**持有 `writer.lock` 时父进程获取超时，释放后可再获取。
