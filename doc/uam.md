# UAM 当前实现说明

## 1. 文档定位

本文档描述的是当前仓库里已经落地的 UAM 实现，而不是纯设计稿。

它主要回答五个问题：

1. UAM 当前接住了 GS 的哪些信息
2. UAM 当前如何接住 gping 的信息
3. SQLite 里已经有哪些正式对象
4. 当前可以怎样查询这些数据
5. 当前边界和后续方向是什么

当前文档基于 2026-04-14 的实现状态。

---

## 2. 当前结论

当前 UAM 已经是一个正式可用的 SQLite 资产状态层，不再是预留钩子。

当前状态可以概括为：

- GS 已经把主机探活、L4 扫描事实、L7 服务识别结果写入 UAM
- gping 已经把 Run、Observation、Claim、Projection 正式写入 UAM
- UAM 已经支持按 IP、端口、协议、tool、run 查询当前状态与历史观察
- UAM 已经能输出综合报告，并支持 gping history 这类面向确认流的查看方式

如果只看当前阶段目标，UAM 已经足够作为 GS + gping 的正式状态承接层。

---

## 3. 当前实现目录

当前 UAM 代码位于：

```text
internal/uam/
  domain/
  normalize/
  project/
  service/
  store/sqlite/
```

### 3.1 `domain/`

负责正式对象和枚举定义：

- `Run`
- `Host`
- `Endpoint`
- `Observation`
- `Claim`
- `HostProjectionCurrent`
- `EndpointProjectionCurrent`
- `ModuleResult`

### 3.2 `store/sqlite/`

负责：

- 打开 SQLite
- 初始化 schema
- 写入 Observation / Claim / ModuleResult
- Upsert Host / Endpoint
- 读写 Projection

### 3.3 `normalize/`

负责把不同生产者的输入归一成 Claim：

- `gs.go`
- `gping.go`
- `module.go`

### 3.4 `project/`

负责 Projection 优先级规则：

- `override > manual > observed > inferred`
- 同优先级下 `newer wins`

### 3.5 `service/`

负责把 ingest / query 做成稳定边界：

- `ingest_gs.go`
- `ingest_gping.go`
- `ingest_module.go`
- `query.go`
- `report.go`

---

## 4. 当前 SQLite 对象

当前已经落地的核心对象如下：

### 4.1 `runs`

表示一次工具执行。

当前 GS / gping / module 都会写入：

- commandline
- targets
- profiles
- ports
- extra_json

### 4.2 `hosts`

当前 Host 身份就是 IP。

### 4.3 `endpoints`

当前 Endpoint 身份是：

- `host_id`
- `protocol`
- `port`

### 4.4 `observations`

Observation 当前承接的是“这次动作到底发生了什么”。

当前会记录：

- tool / module
- route_used
- action_type
- raw_method
- raw_status
- request_summary
- response_summary
- rtt_ms
- error_text
- extra_json
- observed_at

### 4.5 `claims`

Claim 当前承接的是“从 Observation 中提炼出的资产语义”。

当前主要包括：

- `network.reachability`
- `network.port_state`
- `service.name`
- `service.product`
- `service.version`
- `service.info`
- `service.hostname`
- `service.os`
- `service.device`
- `service.banner`
- `service.cpes`
- `user.verification_state`
- `user.override_service_name`

### 4.6 `host_projection_current`

当前保存：

- `current_reachability`
- `reachability_confidence`
- `verification_state`
- `last_seen_at`
- `source_tool`

### 4.7 `endpoint_projection_current`

当前保存：

- `current_port_state`
- `port_state_confidence`
- `current_service`
- `current_product`
- `current_version`
- `current_info`
- `current_hostname`
- `current_os`
- `current_device`
- `current_banner`
- `current_cpes_json`
- `verification_state`
- `last_seen_at`
- `source_tool`

### 4.8 `module_results`

当前已经可写，但当前仓库还没有真正的专项扫描执行器持续写入它。

---

## 5. GS 当前如何进入 UAM

当前 GS 不是只在最后导出画像时顺手存一下，而是沿扫描链多个阶段进入 UAM。

### 5.1 Run 初始化

如果扫描命令带：

```bash
./goscan scan ... --uam-db uam.db
```

系统会先创建一条 `runs` 记录。

### 5.2 主机探活进入 UAM

当前主机探活成功后会写入：

- 一条 Host Observation
- 一条 `network.reachability=reachable` Claim
- HostProjectionCurrent

### 5.3 L4 扫描进入 UAM

当前 UAM 会接住 GS 的 L4 事实，而不是只接最终画像。

包括：

- `tcp-syn`
- `tcp-ack`
- `tcp-window`
- `udp`

### 5.4 L7 enrichment 进入 UAM

当 GS 的 L7 识别拿到结构化结果后，当前会单独写入一条 enrichment Observation，并生成：

- `service.name`
- `service.product`
- `service.version`
- `service.info`
- `service.hostname`
- `service.os`
- `service.device`
- `service.banner`
- `service.cpes`

### 5.5 Projection 刷新

Projection 严格由 Claim 推进，不允许 Observation 直接覆盖当前状态。

---

## 6. gping 当前如何进入 UAM

当前仓库里的 gping 已经不是“只有契约接口”，而是正式执行器。

### 6.1 Run

每次 `goscan gping ... --uam-db uam.db` 执行后，都会创建一条 gping run。

### 6.2 Observation

当前 gping 会把每个 `ActionUnit` 单独写成一条 Observation。

这意味着一条模板动作链会在 UAM 里展开成多条 Observation，而不是一条“混合大结果”。

### 6.3 Claim

当前 gping 会生成并写入：

- `network.port_state`
- `network.reachability`
- `service.name`
- `service.product`
- `service.version`
- `service.banner`
- `http.status_code`
- `http.server`
- `http.title`
- `http.location`
- `tls.subject`
- `tls.issuer`
- `tls.san`
- `tls.alpn`
- `user.verification_state`
- `user.override_service_name`

### 6.4 Projection

当前 gping 可以正式推进：

- Endpoint 当前端口状态
- 当前服务名
- 当前产品 / 版本 / banner
- verification_state

### 6.5 gping 证据

gping 的更多执行证据当前会进入 Observation 的 `extra_json`，例如：

- TLS 握手结构化结果
- HTTP headers
- HTTP body preview
- banner-read 的原始 banner

这些内容当前已经可以通过查询层和 `gping history --verbose` 回看。

---

## 7. 当前查询能力

当前 CLI 已支持：

### 7.1 通用 UAM 查询

```bash
./goscan uam runs --db uam.db
./goscan uam hosts --db uam.db --ip 192.168.1.10
./goscan uam endpoints --db uam.db --ip 192.168.1.10 --port 443
./goscan uam observations --db uam.db --ip 192.168.1.10 --port 443
./goscan uam report --db uam.db --ip 192.168.1.10
```

### 7.2 面向 gping 的查看

```bash
./goscan gping candidates --uam-db uam.db --uam-service https
./goscan gping preview --uam-db uam.db --uam-service https --pick-index 1 --template uam/https-enrich
./goscan gping history --uam-db uam.db --ip 192.168.1.10 --port 443 --protocol tcp --verbose
```

---

## 8. 当前 UAM 的现实意义

当前 UAM 的最大意义已经不是“把结果放进 SQLite”，而是：

1. 把 GS 的发现事实沉淀成正式资产状态
2. 让 gping 可以围绕现有资产做确认与修订
3. 让后续专项扫描有统一入口而不是各自造表

这也是当前项目与单纯扫描器最大的区别。

---

## 9. 当前边界

当前 UAM 已经可用，但边界也很明确：

- 当前已经适合承接 GS 与 gping 第一阶段
- 当前还不是最终的大规模查询优化版本
- 当前还没有正式专项扫描生产者持续写 `module_results`
- 当前还没有完整的人机交互确认界面

---

## 10. 当前阶段结论

如果只站在当前仓库和当前阶段目标来看，UAM 已经达到下面这个标准：

- 可以系统性承接 GS 的主要扫描事实
- 可以承接 gping 第一阶段的定向确认事实
- 可以沉淀为 Host / Endpoint 当前视图
- 可以支持人直接查询和回看
- 可以继续作为未来专项扫描的统一状态入口

所以当前阶段的重点已经不再是“UAM 是否存在”，而是：

> 如何在保持 UAM 稳定边界的前提下，继续把 gping 与未来专项解析器接进来。
