# VaultShare v1 协议规范

本文描述 `ff/` 中实现的线格式、密码学上下文与兑换状态机。实现以代码为准；
文档与代码不一致时视为缺陷，应先修文档或代码，而不是“按习惯理解”。

协议版本 `PROTOCOL_VERSION = 1`。任何字段、标签、绑定字节的改动都必须提升
版本号并给出迁移路径；不得在版本 1 内“顺手”改变语义。

---

## 1. 角色

| 角色 | 持有 | 永远不持有 |
| --- | --- | --- |
| 发送方 | 身份私钥（Ed25519 + X25519）、本地明文目录 | 代理私钥 |
| Web 服务 | 状态文件、KeyConfig/Policy、密文容器、`state_mac_key`、`ipc_hmac_key` | `K_pkg` 明文、`code_mac_key`、代理私钥、明文口令 |
| 密钥代理 | 代理私钥、`code_mac_key`、`state_mac_key`（只读状态） | 发送方私钥、接收方临时私钥 |
| 接收方 | 临时 X25519 私钥、口令、可信的发送方/代理指纹 | 服务器信任（所有服务器返回物都要自己验签） |

---

## 2. 编码约定

所有参与签名、MAC、摘要的 JSON 一律使用**规范化 JSON**：

```
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

UTF-8 编码，无末尾换行。实现见 `vaultshare/util/canonical.py`。

- 二进制字段在 JSON 中统一为 **base64url（无 `=` 填充）** 字符串。
- 十六进制标识符一律小写、无前缀：
  - `package_id`、`grant_id`、`sender_key_id`、`key_id`、`authorization_id`、
    `reservation_id`、`batch_id`：16 字节（32 个十六进制字符）；
  - `request_id`：32 字节（64 个十六进制字符）；
  - `code_verifier`、`*_hash`、`*_sha256`、`signature` 摘要：32 字节（64 hex）
    或 base64url 64 字节签名。
- 时间戳统一为 Unix 秒（整数）。
- 所有结构都带 `format` 与 `version`，并做**字段集合精确匹配**：出现额外字段
  即拒绝，避免“塞进签名字段却没人校验”。

### 2.1 `fixed_domain`

HPKE `info` 与签名域前缀共用的无歧义编码：

```
fixed_domain(domain, part1, ...) =
    u32be(len(domain)) || domain
    || u32be(len(part1)) || part1
    || ...
```

长度前缀防止 `"ab"||c` 与 `"a"||bc` 相撞。

---

## 3. 签名

`Ed25519.sign(domain || SHA256(canonical(obj_without_signature)))`。

- 签名对象中的 `signature` 字段是 base64url 字符串；计算时先去掉该字段。
- 不同对象使用不同域标签（`vaultshare/crypto/keys.py`）：

| 域标签 | 用途 |
| --- | --- |
| `VaultShare/sig/keyconfig/v1` | KeyConfig |
| `VaultShare/sig/policy/v1` | SharePolicy |
| `VaultShare/sig/sender-identity/v1` | 发送方身份记录 |
| `VaultShare/sig/receipt/v1` | 交付回执 |
| `VaultShare/sig/authorization/v1` | 预授权票据 |
| `VaultShare/sig/grant-batch/v1` | 批量授权请求 |
| `VaultShare/sig/upload-key/v1` | 上传凭据 |

域分离保证一条签名不能在对象类型之间搬运。

---

## 4. HPKE 套件与上下文绑定

### 4.1 固定套件

- KEM：`DHKEM(X25519, HKDF-SHA256)`（0x0020）
- KDF：`HKDF-SHA256`（0x0001）
- AEAD：`AES-128-GCM`（0x0001）
- 模式：Base（0x00），单次 Seal/Open
- 套件名（KeyConfig 中）：`HPKE-X25519-HKDF-SHA256-AES128GCM`

线格式：`enc(32) || ciphertext(明文长度 + 16 tag)`。JSON 中拆为
`{"enc": b64url, "ciphertext": b64url}`。

### 4.2 与 RFC 9180 的偏差（重要）

**本协议没有使用 RFC 9180 的 `aad` 参数，而是把所有上下文绑定字节放进
`info`。**

原因：`cryptography` 50.0.2 的 `hpke.Suite.encrypt` / `decrypt` 签名是

```python
encrypt(plaintext, public_key, info=None)   # 没有 aad
decrypt(encapped, private_key, info=None)
```

底层实现不接受逐消息 AAD。把上下文放进 `info` 后：

- `info` 进入 HPKE key schedule（`info_hash`），任何字段改动都会导致解封失败，
  认证强度等价于“绑定进 AEAD”；
- 不同用途使用不同标签，跨用途重放（例如把 `code` 密文当兑换请求提交）会被
  认证失败拒绝；
- **但不与 RFC 9180 附录 A 的官方测试向量逐字节兼容**：附录 A 的向量使用非空
  AAD（如 `Count-0`），无法用该 API 复现。

因此本仓库不声称“通过 RFC 9180 测试向量”。替代验证见
`ff/tests/test_hpke_reference.py`：按 RFC 9180 定义独立实现 key schedule 与
封装（空 AAD），与库实现双向互测，覆盖套件参数、suite_id、标签、长度与派生
顺序。该文件不能发现“AAD 位置偏差”本身，偏差由本节显式记录。

将来若库暴露 AAD 或替换为 RFC 完整实现，必须升级协议版本，而不是静默改变
含义。

### 4.3 各用途的 `info`

实现见 `protocol/signing.py`。所有字段都是解码后的原始字节，不是 JSON 文本。

| 用途 | 标签（`fixed_domain` 第一段） | 后续字段 |
| --- | --- | --- |
| KeyConfig `K_pkg` | `VaultShare/kc/v1` | `package_id(16)`、`policy_hash(32)` |
| 上传凭据 `K_pkg` | `VaultShare/upload-key/v1` | `package_id(16)`、`payload_sha256(32)`、`sender_identity_hash(32)`、`server_url(UTF-8)` |
| 兑换请求 | `VaultShare/redeem/v1` | `package_id(16)` |
| 口令密封 | `VaultShare/code/v1` | `package_id(16)`、`grant_id(16)`、`sender_x25519_pk(32)` |
| 密钥信封 | `VaultShare/envelope/v1` | `package_id(16)`、`grant_id(16)`、`request_id(32)`、`sha256(recipient_pk)(32)`、`config_version(u32be)` |

注意 `policy_hash` 在 `info` 中是 32 字节**原始摘要**（由 64 位十六进制解码）。
`recipient_pk_hash` 同理。

---

## 5. 身份与信任锚

### 5.1 发送方身份记录

```json
{
  "format": "vaultshare-sender-identity",
  "version": 1,
  "sender_key_id": "<32 hex>",
  "ed25519_public_key": "<b64url32>",
  "x25519_public_key": "<b64url32>",
  "created_at": 1234567890,
  "signature": "<b64url64>"
}
```

- 签名由 `ed25519_public_key` 对除 `signature` 外的规范化内容生成。
- `sender_identity_hash = SHA256(canonical(除 signature 外))`。
- Ed25519（签名）与 X25519（接收口令密文）绑定在同一条记录里。
- KeyConfig 与 Policy 必须引用同一个 `sender_key_id`、
  `sender_identity_hash`、`sender_public_key`；三者任一不一致即拒绝。
- 注册、撤销写审计。服务器保存完整记录到状态文件 `senders`。
- 接收方首次使用通过可信渠道核对并固定 `sender_identity_hash`（TOFU）。
  服务器不能替换发送方公钥：接收方用该指纹核对服务器返回的身份记录。

### 5.2 代理身份与指纹

```json
{
  "format": "vaultshare-broker-identity",
  "version": 1,
  "key_id": "<32 hex>",
  "hpke_public_key": "<b64url32>",
  "signing_public_key": "<b64url32>",
  "fingerprint": "<64 hex>",
  "created_at": 1234567890
}
```

```
fingerprint = SHA256(canonical({
    "key_id": key_id,
    "hpke_public_key": hpke_public_key_b64,
    "signing_public_key": signing_public_key_b64
}))
```

- 该记录**不是**由代理私钥签名的，真实性完全来自带外核对的指纹。
- 发送方在打包前必须取得该记录并重新计算指纹；`pack` 强制要求
  `--broker-identity`，可选再传 `--broker-fingerprint`。
- KeyConfig 中记录该指纹，并由发送方签名；服务器与接收方都不得替换。

---

## 6. KeyConfig

```json
{
  "format": "vaultshare-keyconfig",
  "version": 1,
  "package_id": "<32 hex>",
  "suite": "HPKE-X25519-HKDF-SHA256-AES128GCM",
  "broker": {
    "key_id": "<32 hex>",
    "hpke_public_key": "<b64url32>",
    "signing_public_key": "<b64url32>",
    "fingerprint": "<64 hex>"
  },
  "hpke_wrap": {"enc": "<b64url32>", "ciphertext": "<b64url48>"},
  "policy_hash": "<64 hex>",
  "sender_key_id": "<32 hex>",
  "sender_identity_hash": "<64 hex>",
  "sender_public_key": "<b64url32>",
  "created_at": 1234567890,
  "signature": "<b64url64>"
}
```

- `hpke_wrap` 是 32 字节 `K_pkg` 封给代理 HPKE 公钥的结果，`ciphertext`
  必须恰为 48 字节（32 + 16 tag）。
- 验证顺序：结构/字段集合 → 套件 → 内嵌指纹与公钥一致性 → 发送方签名 →
  与已注册身份的字段核对（`check_sender_fields`）。
- 服务端创建包时还会向在线代理取当前身份，核对 `key_id` 与两把公钥一致。

### 6.1 上传凭据 `upload-key.json`

“只加密、后上传”模式在加密时还不知道口令数量、次数、有效期，因此不能生成
KeyConfig/Policy。加密工具把 `K_pkg` 用**发送方身份中的 X25519 公钥**密封，
写入 `upload-key.json`；上传步骤再解封并按当时选择生成 Policy/KeyConfig。

```json
{
  "format": "vaultshare-upload-key",
  "version": 1,
  "package_id": "<32 hex>",
  "server": "https://host",
  "payload_sha256": "<64 hex>",
  "suite": "HPKE-X25519-HKDF-SHA256-AES128GCM",
  "sender_key_id": "<32 hex>",
  "sender_identity_hash": "<64 hex>",
  "sender_public_key": "<b64url32>",
  "hpke_wrap": {"enc": "<b64url32>", "ciphertext": "<b64url48>"},
  "created_at": 1234567890,
  "signature": "<b64url64>"
}
```

- `hpke_wrap` 的明文是 32 字节 `K_pkg`；上下文见 §4.3，绑定包 ID、容器摘要、
  发送方身份摘要与规范化后的服务器地址。任一字段不符都无法解封。
- 记录由发送方 Ed25519 签名；上传步骤验证签名、身份绑定、`payload_sha256`
  与 `package.json` 一致，并用解出的 `K_pkg` 完整解密一遍容器后才生成策略。
- 文件不含明文 `K_pkg`，单独泄露不足以解密或伪造分享；但上传步骤仍需要发送方
  身份私钥与口令（用于解封和签名 Policy/KeyConfig），长期密钥不会被复制进文件。
- 上传完成后 `upload-key.json` 保留，便于重试上传；它不能替代 KeyConfig。

---

## 7. SharePolicy 与额度

```json
{
  "format": "vaultshare-policy",
  "version": 1,
  "package_id": "<32 hex>",
  "max_codes": 5,
  "max_uses_per_code": 3,
  "max_total_redemptions": 15,
  "allow_any_recipient": true,
  "latest_expiry": 1234567890,
  "policy_version": 1,
  "sender_key_id": "<32 hex>",
  "sender_identity_hash": "<64 hex>",
  "sender_public_key": "<b64url32>",
  "created_at": 1234567890,
  "signature": "<b64url64>"
}
```

- `allow_export` 被刻意移除：接收方拿到 `K_pkg` 后无法被远程限制导出，保留该
  字段只会制造虚假的安全承诺。
- `policy_hash = SHA256(canonical(policy))`（含 `signature`），写入 KeyConfig。
- 结构约束：`max_uses_per_code <= max_total_redemptions`、
  `latest_expiry > created_at`、`allow_any_recipient` 必须为 `true`。
- 累计额度校验**在同一把状态锁内、基于整个包的全部 grant 重新计算**，不信任
  缓存计数器（`grant_metrics`）：
  - `已签发数 + 本次新增 <= max_codes`
  - `Σ(max_uses) + 本次新增分配 <= max_total_redemptions`
  - 单次 `uses_per_code <= max_uses_per_code`
  - `expires_at <= latest_expiry`
  - 任意时刻 `Σused <= Σmax_uses` 且 `Σused <= max_total_redemptions`
- 违反任一条返回 `quota_denied`，整个事务不提交。分批请求无法绕过。

---

## 8. 口令（grant）与密封

- 明文口令：26 个 Crockford Base32 字符（约 130 bit），显示为
  `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`。
- 归一化：转大写、忽略分隔符/空格，`O→0`、`I→1`、`L→1`。兑换请求内层只接受
  已归一化形式。
- 服务器只保存 `code_verifier = HMAC-SHA256(code_mac_key, normalized_ascii)`
  （64 hex）。`code_mac_key` **只有代理读取**。
- 代理生成明文口令后立即用发送方身份记录中的 X25519 公钥密封：

```
sealed_code = HPKE.seal(
    sender_x25519_public,
    normalized_code_ascii,
    fixed_domain("VaultShare/code/v1", package_id, grant_id, sender_x25519_public)
)
```

返回 `{"enc", "ciphertext"}`。明文口令只存在于代理内存中，随即丢弃。

grant 记录字段：`grant_id`、`package_id`、`code_verifier`、`sealed_code`、
`expires_at`、`max_uses`、`used`、`revoked`、`policy_version`、`batch_id`、
`created_at`。字段集合精确匹配。

创建口令使用 `batch_id` 幂等：代理按 `grants:<batch_id>` 缓存结果；服务端在
同一事务内按 `batch_id` 去重并重新校验累计额度。重试不会重复发码或重复计数。

---

## 9. 兑换请求

外层（HTTP 明文，Web 可见）：

```json
{
  "request_id": "<64 hex>",
  "package_id": "<32 hex>",
  "hpke_enc": "<b64url32>",
  "ciphertext": "<b64url>"
}
```

内层（HPKE 密文，只有代理能解）：

```json
{
  "format": "vaultshare-redeem",
  "version": 1,
  "request_id": "<64 hex>",
  "package_id": "<32 hex>",
  "recipient_public_key": "<b64url32>",
  "code": "<归一化 Crockford>",
  "created_at": 1234567890,
  "nonce": "<b64url16>"
}
```

- `info = fixed_domain("VaultShare/redeem/v1", package_id)`。
- 内层字段集合精确匹配；`format`/`version` 必须正确；内层 `request_id`、
  `package_id` 必须与外层一致（防止请求被挂到另一个包上）。
- 内层规范化 JSON 上限 4096 字节；密文长度必须在 `[16, 4096+16]`。
- `created_at` 允许 ±600 秒时钟偏差（`MAX_SKEW`）。
- `request_id` 是 256 bit 随机值，同时承担幂等键与去重键。
- Web 只转发外层；它无法解出接收方公钥或口令。

---

## 10. 预授权票据

代理在通过口令、策略、有效期、撤销、`used < max_uses` 校验后返回票据：

```json
{
  "format": "vaultshare-authorization",
  "version": 1,
  "authorization_id": "<32 hex>",
  "grant_id": "<32 hex>",
  "request_id": "<64 hex>",
  "recipient_pk_hash": "<64 hex>",
  "package_id": "<32 hex>",
  "policy_hash": "<64 hex>",
  "state_generation": 42,
  "state_digest": "<64 hex>",
  "issued_at": 1234567890,
  "expires_at": 1234568010,
  "broker_key_id": "<32 hex>",
  "signature": "<b64url64>"
}
```

- `expires_at = issued_at + 120` 秒（`TICKET_TTL`）。
- `state_digest = SHA256(canonical(完整状态信封，含 mac))`，只代表**预授权时**
  的快照，不是交付凭据。
- 字段集合、ID 长度、摘要长度、时间范围全部硬校验。
- 票据签名用该包绑定的代理 Ed25519 密钥，域标签
  `VaultShare/sig/authorization/v1`。
- 票据不能单独换到密钥：交付前代理还会核对已持久化的 `RESERVED` 记录。

---

## 11. 密钥信封与回执

为避免回执哈希循环依赖，信封拆为 `envelope_core` 与 `receipt`：

```json
{
  "envelope_core": {
    "format": "vaultshare-envelope",
    "version": 1,
    "package_id": "<32 hex>",
    "grant_id": "<32 hex>",
    "request_id": "<64 hex>",
    "recipient_pk_hash": "<64 hex>",
    "config_version": 1,
    "key_id": "<32 hex>",
    "hpke_enc": "<b64url32>",
    "ciphertext": "<b64url48>"
  },
  "receipt": {
    "format": "vaultshare-receipt",
    "version": 1,
    "issued_at": 1234567890,
    "envelope_sha256": "<64 hex>",
    "broker_signature": "<b64url64>"
  }
}
```

**`envelope_sha256 = SHA256(canonical(envelope_core))`，只覆盖
`envelope_core`，绝不包含 `receipt` 自身。** 这是唯一允许的定义；把完整信封
纳入哈希是不可计算的循环依赖。

回执签名对象是：

```json
{
  "format": "vaultshare-receipt",
  "version": 1,
  "issued_at": 1234567890,
  "envelope_sha256": "<64 hex>",
  "signature": "<同 broker_signature>"
}
```

接收方校验顺序（`protocol/envelope.py::open_envelope`，任一步失败即停止）：

1. 用 KeyConfig 中**发送方签过名**的代理签名公钥验证回执，并重算
   `envelope_sha256` 比对；
2. `envelope_core` 字段集合与版本；
3. `package_id`、`grant_id`、`request_id`、`recipient_pk_hash`
   （由本地私钥推导）、`config_version`、`key_id` 全部与本地期望一致；
4. HPKE 解封得到 32 字节 `K_pkg`。

`K_pkg` 的 HPKE 绑定见 §4.3。代理在交付后立即 `wipe` 本进程副本。

---

## 12. 代理 IPC

### 12.1 传输

- 只绑定回环地址（启动时强制检查）；不支持远程代理。
- 长度前缀帧：`u32be(len) || canonical_json`，上限 4 MiB。
- 每次调用一个 TCP 连接，请求/响应各一帧。

### 12.2 请求消息

```json
{
  "v": 1,
  "seq": 7,
  "ts": 1234567890,
  "request_id": "<64 hex>",
  "body_sha256": "<64 hex>",
  "op": "authorize",
  "body": {},
  "mac": "<hex>"
}
```

```
mac = HMAC-SHA256(ipc_hmac_key, canonical({
    "v", "seq", "ts", "request_id", "body_sha256", "op", "body"
}))
```

规划阶段写的是字段拼接；实现改为对具名对象做规范化 JSON，字段集合由
`sort_keys` 固定，消除长度歧义。**这是实现事实，协议与审计以本节为准。**

校验顺序：字段集合 → `v == 1` → MAC（常量时间比较）→ `ts` 在 ±60 秒内 →
`body_sha256 == SHA256(canonical(body))` → 重放/幂等。

### 12.3 响应消息

```json
{"v": 1, "ts": ..., "request_id": ..., "ok": true, "code": "", "message": "", "body": {}, "mac": "..."}
```

MAC 对除 `mac` 外的具名字段做同样的规范化 HMAC。客户端必须验 MAC、校验
`request_id`、版本与时间戳后才可信任内容。错误通过 `ok=false` + `code` 返回；
代理内部异常只回 `internal`，不泄露堆栈。

### 12.4 重放与幂等

- 进程内有界重放缓存：键 `(request_id, body_sha256, op)`，TTL 600 秒，上限
  4096 条。命中时返回同一逻辑结果（重新签名时间戳）。
- 同一 `request_id` 携带不同 `body_sha256` 一律拒绝（`request_id_reuse`）。
- 持久幂等（跨重启，`data/broker/idempotency.json`，原子写）：
  - `grants:<batch_id>`：30 天；
  - `authorize:<request_id>:<body_sha256>`：480 秒。
  文件损坏视为代理不可用，而不是清空缓存继续跑。
- 信封缓存（`data/broker/envelopes/<request_id>.json`）：以 `request_id` 为
  键、同时保存请求摘要；同键不同内容即拒绝。缓存只含已签名信封，不含
  `K_pkg`。

### 12.5 操作

| op | body | 返回 |
| --- | --- | --- |
| `health` | `{}` | `{status, key_id, fingerprint, time}` 或降级信息 |
| `get_identity` | `{}` | `{identity: <代理身份记录>}` |
| `create_grants` | `batch_id, package_id, count, uses_per_code, expires_at, policy_version` | `{batch_id, grants:[...]}` |
| `authorize` | `outer, state_generation, state_digest` | `{ticket}` |
| `deliver` | `outer, ticket, reservation_id` | `{envelope, request_digest}` |

`authorize` 在状态快照变化时返回 `state_changed`，服务端重新取快照重试；
`deliver` 必须验证票据与已提交的 `RESERVED` 记录（见 §14）。

---

## 13. 容器 `payload.vspk`

```
v3 header = "VSPK"(4) | version=3(1) | package_id(16) | suite=1(u16be) |
            flags(1) | server_url_len(u16be) | server_url(UTF-8) |
            secretstream_header(24)
v2 header = "VSPK"(4) | version=2(1) | package_id(16) | suite=1(u16be) |
            server_url_len(u16be) | server_url(UTF-8) | secretstream_header(24)
v1 header = "VSPK"(4) | version=1(1) | package_id(16) | suite=1(u16be) |
            secretstream_header(24)          # 仅读取兼容
then repeated:
    u32be(ct_len) || ciphertext
```

- 当前打包端写 v3；读取端同时接受 v1（`server_url` 视为空）与 v2（视为
  “必须核对指纹”）。未知 flags 位一律拒绝，避免降级歧义。
- `flags` 第 0 位 = `require_sender_fingerprint`：发送方要求接收方在兑换前
  核对发送方身份指纹。v1/v2 没有该字段，读取时按 `true` 处理。它决定接收方
  工具是否显示并强制指纹输入。**它是发送方的偏好声明，不是信任锚**：flag 虽在
  AAD 覆盖范围内，但只有拿到 `K_pkg` 后才会被认证；能替换整个容器的攻击者
  也能把它改成 0。因此不能把“flag=0”解释为身份已经过验证。
- `server_url` 是**给接收方的提示**，最多 512 字节，只允许 `http(s)://`、
  不含账号密码/查询串/片段。它在头部明文可见，打包时写入、AAD 覆盖；取得
  `K_pkg` 后被改动会导致首个分块认证失败。它**不是信任锚**：接收方仍须用
  带外渠道核对的发送方/代理指纹，不能因为容器里写了地址就相信服务器。
- 加密：`crypto_secretstream_xchacha20poly1305`（PyNaCl/lib sodium），chunk 4 MiB。
- `K_stream = HKDF-SHA256(K_pkg, salt=package_id, info=b"VaultShare/container/v1")`，32 字节。
  （容器版本升级不改变该 KDF 标签，v2 只是头部多了一个提示字段。）
- `AAD = 完整 header || msg_index_u32be || ct_len_u32be`。长度字段本身也进入
  AAD，篡改 `ct_len` 会变成认证失败；实现先校验 `ct_len` 范围再读取，避免
  4 字节篡改逼出巨大内存分配。
- 分享卡片（`vaultshare-share-card`）是另一份可选的小 JSON：包 ID、服务器
  地址、发送方/代理指纹，以及可选的第一个口令。它只减少手工输入，同样不是
  信任锚；附带口令时卡片本身即凭证。
- 明文流第一条消息为 `u32be(manifest_len) || manifest_json`，其后按 manifest
  中文件顺序拼接文件字节；最后一条实际消息带 `TAG_FINAL`。
- manifest：

```json
{
  "format": "vaultshare-manifest",
  "version": 1,
  "package_id": "<32 hex>",
  "entries": [{"path": "a/b.txt", "type": "file", "size": 12, "mime": "text/plain"}],
  "total_files": 1,
  "total_bytes": 12
}
```

- 打包与解包的路径规则（Windows + POSIX 双重）：
  - 拒绝绝对路径、盘符相对路径、UNC、`..`、ADS（含 `:`）、Windows 保留设备名
    （CON/PRN/AUX/NUL/COM1-9/LPT1-9 等）、结尾点或空格；
  - 大小写冲突、文件/目录同名冲突拒绝；
  - 打包时拒绝符号链接/重解析点；解包时不跟随链接，每个目标再用
    `ensure_within` 核对仍在输出目录内；
  - 写入使用 `O_EXCL`，绝不覆盖已有文件；先解到受控 staging，全部成功后才
    提交到输出目录，失败清理 staging。
- 解包后仍有剩余明文字节、或实际字节数与 manifest 不一致，均拒绝。

### 13.1 交付方式与密文来源

包记录上的 `payload_mode` 决定密文放在哪里（默认 `server`）：

| 值 | 服务器 | 接收方取得密文 |
| --- | --- | --- |
| `server` | 接收 `PUT /blob`，保存 `payload.vspk` | 兑换后 `GET /blob` 下载 |
| `local` | **不接收密文**，只存 KeyConfig、Policy、口令与密钥信封 | 由发送方直接给出容器 |

- `POST /api/v1/packages` 接受 `payload_mode`，只允许 `server`/`local`，写入状态
  并审计；`GET /api/v1/packages/<id>/public` 返回同一字段。缺少该字段的旧状态
  一律按 `server` 解释。
- `local` 包的 `payload_sha256` 为空、`payload_size` 为 0，不写 `payload.vspk`；
  `require_payload` 检查跳过它，所以仍可创建口令与兑换。`server` 包缺少
  `payload_sha256` 时继续按“尚未上传”拒绝。
- 对 `local` 包：`PUT /blob` 返回 409 `local_payload`，`GET /blob` 返回 404
  `local_payload`。
- 同一 `package_id` 一旦以某种方式创建，重复上传时若 `payload_mode` 不同就
  直接失败，避免同一包在不同接收方之间出现两种密文来源。
- 接收方带本地容器兑换时，**在提交兑换请求前**先读容器头部核对
  `package_id`；若公开材料里有 `payload_size`/`payload_sha256`（服务器交付的
  包），也在此处比对。校验失败不提交兑换，因此不消耗次数。
- 本地交付不改变密码学边界：服务器仍然见不到 `K_pkg` 与明文，口令仍需兑换
  才能解封；它只减少了不必要的大文件上传。

---

## 14. 兑换状态机

三阶段：**预授权 → 提交预留（唯一扣减点）→ 验证已提交预留后交付**。

### 14.1 正常路径

1. 服务端校验未降级、package 存在且 `status=active`、发送方身份未撤销。
2. 若 `requests[request_id]` 已存在：
   - `DELIVERED`：返回缓存信封，**不扣次数**；
   - `RESERVED`：跳过预授权，直接重新交付，**不扣次数**；
   - `DENIED`：返回原拒绝原因。
3. **预授权**：读取状态快照（完整信封 + `generation` + `state_digest`），
   不持状态锁调用代理 `authorize`。代理解密请求、校验口令 HMAC、发送方绑定、
   策略签名、package/grant 状态、有效期、撤销、`used < max_uses`，返回票据。
4. **提交预留**（权威扣减点）：重新加锁，如果期间出现同 `request_id` 的记录
   则回到第 2 步；否则再次校验 grant/package 与累计额度，并在同一事务内：
   - `grant.used += 1`，`grants_counters[package_id]` 由全部 grant 重算；
   - 写入 `requests[request_id] = RESERVED`，含 `authorization_id`、
     `reservation_id`、`grant_id`、`recipient_pk_hash`、`opaque_request`
     （外层请求的规范化摘要）、`ticket`、`state_generation`；
   - 计算覆盖完整状态信封的 MAC，追加 journal，原子替换 `state.json`。
   额度一经占用**永不恢复**。
5. **交付**：调用代理 `deliver`。代理：
   - 验证票据签名、字段、有效期、`broker_key_id` 与请求内容；
   - 只读打开 `state.json` 并验证完整信封 MAC；
   - 要求存在唯一匹配的 `RESERVED` 记录：`request_id`、`grant_id`、
     `recipient_pk_hash`、`authorization_id`、`reservation_id` 全部一致，
     且 grant 的 `used >= 1`；任何一项不符返回 `reservation_invalid`；
   - 解封 `K_pkg`、按 §11 重封给接收方、按 `(request_id, 请求摘要)` 写缓存、
     返回信封，随后 `wipe(K_pkg)`。
6. 服务端再次加锁写入 `DELIVERED` 与信封，提交状态后返回。重试命中状态或
   代理缓存得到**字节一致**的信封。

### 14.2 失败路径

| 场景 | 结果 |
| --- | --- |
| 预授权前被拒（口令错误/过期/耗尽/撤销） | 一律 403 `invalid_code`「口令无效」，无预留，不扣额度（原因只进代理审计日志） |
| 预授权后、提交预留前失败 | 无状态变更；同一 `request_id` 可重试 |
| 预留提交后代理拒绝/不可达 | 保留 `RESERVED`，返回 503；重试只重新交付，不再扣次数 |
| 票据过期 | 同一 `request_id` 重新预授权；grant 已耗尽也可放行**完全匹配的预留**，但撤销仍拒绝 |
| 磁盘写失败 | 返回 503；若 journal 已提交而 state 未替换，重启回放完成；绝不回滚 `used` |
| 状态损坏 | 兑换返回 503，不重置任何授权 |
| 新 `request_id` 抢占最后一个名额 | 预留事务串行化，在锁内看到额度耗尽而被拒 |

重新预授权时若代理返回授权不可用（`Gone`），预留已经占用额度，不能被当成
“未发生”；服务端返回 `reservation_stuck` 并保留记录，交由人工检查。

---

## 15. 版本演进

- `PROTOCOL_VERSION` 同时写入所有格式对象与状态信封。解析器拒绝未知版本。
- 增加字段 = 破坏性变更（字段集合精确匹配），必须提升版本并提供迁移脚本。
- 替换 HPKE 套件、改变 `info` 内容或位置（如引入 AAD）必须提升版本。
- 容器版本与套件 ID 独立；不支持的组合直接拒绝。当前打包写 v3；读取端兼容
  v1（无服务器地址提示）与 v2（无指纹核对标记，按必须核对处理）。新增头部
  字段时继续提升容器版本，不改变 `K_stream` 标签与分块布局。
- 程序版本（`__version__`）与协议版本无关。

---

## 16. 测试映射

| 主题 | 测试文件 |
| --- | --- |
| 规范化、签名、HPKE、口令、路径 | `tests/test_primitives.py` |
| HPKE 独立参考实现交叉对测 | `tests/test_hpke_reference.py` |
| 容器打包/解包/路径安全 | `tests/test_container.py` |
| 指纹核对可选与其余验证 | `tests/test_redeem_fingerprint.py` |
| 本地交付（不传密文）与 blob 拒绝 | `tests/test_local_delivery.py` |
| 状态 MAC、journal、降级、恢复 | `tests/test_state.py` |
| IPC MAC、时间戳、重放、幂等 | `tests/test_ipc.py` |
| 兑换状态机、并发、多进程 | `tests/test_redeem.py` |
| Web 认证、CSRF、锁定、API 隔离 | `tests/test_web.py` |
| 身份私钥文件 | `tests/test_identity.py` |
| 全链路子进程验收 | `tests/test_e2e.py`、`tools/e2e_check.py` |
