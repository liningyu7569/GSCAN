# gping 第二阶段实现状态

## 1. 文档定位

本文档描述的是当前仓库里已经落地的 `gping` 第二阶段实现状态，而不是纯设计稿。

设计目标、边界讨论和方法论补充仍然以项目根目录的 [gping.md](../gping.md) 与 `Docs/` 中的协议讨论稿为准；本文档更关注：

1. 当前 `gping` 已经能做什么
2. 当前 `DSL v1 / adapter v1 / extract / recommend` 已经到哪一步
3. 当前独立运行能力与 UAM 写回能力分别到什么程度
4. 当前仍然刻意没有进入 `gping` 的边界是什么

当前文档基于 2026-04-15 的实现状态。

---

## 2. 当前结论

当前 `gping` 已经从“第一阶段最小闭环”推进到“第二阶段主骨架收口”。

它现在同时具备两种正式身份：

1. 一个可以脱离 UAM 独立运行的定向探测器
2. 一个可以围绕 UAM 当前资产做轻量确认、修订和 enrich 的确认器

当前主链已经稳定形成：

1. 解析目标
2. 从 UAM 选择候选资产或直接解析字面目标
3. 预览模板 / 动作链
4. 执行动作
5. 解释证据为 Observation / Claims / Recommendation
6. 写回 UAM
7. 回看 gping 历史

如果只看第二阶段主线目标，当前 `gping` 已经基本成型。

---

## 3. 当前结构

当前 `gping` 仍保持三条执行路线：

- `raw`
- `stack`
- `app`

但其中 `app` 已正式引入 `adapter` 子层。

核心目录如下：

```text
cmd/gping.go
internal/gping/
  resolver.go
  planner.go
  preview.go
  execute.go
  raw.go
  stack.go
  app.go
  app_adapter*.go
  interpret.go
  template_execution.go
  history.go
  templates/
```

其中：

- `resolver.go` 负责统一解析字面目标、URL、`--uam-endpoint`、UAM 条件筛选
- `planner.go` 负责把显式参数或模板展开为 `ActionUnit`
- `raw.go / stack.go / app.go` 负责三条路线的执行
- `app_adapter*.go` 负责协议级轻量动作执行
- `interpret.go` 负责把证据解释为 Observation / Claims
- `template_execution.go` 负责 `when / extract / recommend`
- `history.go` 负责从 UAM 回看 gping 历史

---

## 4. 当前支持的命令

### 4.1 主命令

```bash
./goscan gping ...
```

### 4.2 模板查看

```bash
./goscan gping templates
./goscan gping templates --show uam/mysql-enrich
```

### 4.3 候选目标查看

```bash
./goscan gping candidates --uam-db uam.db --uam-service ssh
```

### 4.4 执行前预览

```bash
./goscan gping preview --ip 192.0.2.10 --port 21 --template uam/ftp-enrich
```

### 4.5 历史回看

```bash
./goscan gping history --uam-db uam.db --ip 192.0.2.10 --port 443 --protocol tcp --verbose
```

---

## 5. 当前支持的方法

### 5.1 raw

- `tcp-syn`
- `tcp-raw`
- `icmp-echo-raw`
- `icmp-raw`

### 5.2 stack

- `tcp-connect`
- `banner-read`
- `tls-handshake`

### 5.3 app

- HTTP
  - `http-head`
  - `http-get`
  - `http-post`
- DNS
  - `dns-query`
- FTP
  - `ftp-banner`
  - `ftp-feat`
  - `ftp-auth-tls`
- SMTP
  - `smtp-banner`
  - `smtp-ehlo`
  - `smtp-starttls`
- Redis
  - `redis-ping`
  - `redis-info-server`
  - `redis-info-replication`
- SSH
  - `ssh-banner`
  - `ssh-kexinit`
  - `ssh-hostkey`
- MySQL
  - `mysql-greeting`
  - `mysql-capabilities`
  - `mysql-starttls`

---

## 6. 当前 Raw 注入能力

`raw` 路线现在不再只是硬编码的 `tcp-syn / icmp-echo`，已经开始具备独立运行时的 Nping 风格常见注入面。

当前 CLI 已支持的常见 raw 参数包括：

- `--retries`
- `--ttl`
- `--tos`
- `--ip-id`
- `--df`
- `--badsum`
- `--source-port`
- `--tcp-flags`
- `--tcp-seq`
- `--tcp-ack`
- `--tcp-window`
- `--icmp-id`
- `--icmp-seq`
- `--icmp-type`
- `--icmp-code`
- `--payload`
- `--payload-hex`

当前 raw 路线已经支持：

- IPv4 `TTL / TOS / ID / DF`
- TCP `flags / seq / ack / window / source port`
- ICMP `type / code / id / seq`
- 文本 payload 与十六进制 payload
- 故意破坏 transport checksum
- raw 动作级重试

当前仍然没有进入的更深层实验能力包括：

- 自定义源 IP / MAC 欺骗
- 自定义 BPF / matcher DSL
- 多包序列化实验
- UDP raw 路线
- 更完整的畸形包矩阵

也就是说：`gping raw` 现在已经可以承担常见自由注入探测，但还不是完整的 Nping 替代品。

---

## 7. 当前模板系统

### 7.1 当前形态

当前模板系统已经进入兼容式 `DSL v1`：

- 旧 `actions:` 模板仍兼容
- 新模板优先使用 `workflow:`

### 7.2 当前顶层字段

- `kind`
- `name`
- `description`
- `applies_to`
- `vars`
- `workflow`
- `actions`
- `extract`
- `recommend`
- `suggest`

### 7.3 当前动作字段

- `id`
- `name`
- `route`
- `adapter`
- `method`
- `url`
- `host_header`
- `sni`
- `path`
- `body`
- `payload`
- `read_bytes`
- `headers`
- `params`
- `when`
- `continue_on_error`
- `insecure_skip_verify`

### 7.4 当前已经落地的 DSL 能力

- 模板变量展开
- `workflow` 动作链
- 动作级 `params`
- `when` 条件执行
- `continue_on_error`
- `extract` 到 claims
- `recommend` 作为建议层输出
- `suggest` 作为轻量提示层输出

### 7.5 当前注释模板示例

当前仓库中的示例模板位于：

- [doc/examples/gping-template-example.yaml](/Users/liningyu/Documents/GSCAN_2_gping/doc/examples/gping-template-example.yaml:1)

---

## 8. 当前和 UAM 的关系

当前 `gping` 已经正式对接 UAM。

### 8.1 已完成

- gping Run 写入
- Observation 写入
- Claim 写入
- `extra_json` 证据落库
- `verification_state`
- `override_service_name`
- Endpoint / Host Projection 推进
- `history` 回看

### 8.2 当前工作方式

一条模板动作链会展开成多条 Observation，但共享同一个 gping run。

这保证了：

- 每个动作都可追溯
- 每个动作都能独立产出证据
- Projection 推进有明确依据

---

## 9. 当前边界

当前 `gping` 已经不是只服务 HTTP 的原型，但它仍然坚持同一个边界：

- 进入 `gping` 的是轻量、确认级、低副作用动作
- 不进入 `gping` 的是深交互、重状态、强业务语义能力

因此当前明确不做：

- FTP 登录后目录 / 数据通道行为
- SMTP / MySQL / Redis 认证后深交互
- SSH 认证与会话执行
- 专项安全审计逻辑
- 重型批量协议扫描器

---

## 10. 当前阶段判断

截至 2026-04-15，`gping` 第二阶段的主骨架已经基本收口：

- `DSL v1`
- `app adapter v1`
- `extract / recommend` 接缝
- 常见协议轻量 adapter
- 独立运行入口
- UAM 写回闭环
- 常见 raw 注入参数面

如果继续推进，后续重点已经不再是“把骨架搭出来”，而是：

1. 继续打磨 raw route 的实验能力边界
2. 收紧 recommendation 与 extract 的语义质量
3. 做更多协议模板与执行器的一致性打磨
