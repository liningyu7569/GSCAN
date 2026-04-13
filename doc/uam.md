# UAM 当前实现说明

## 1. 文档定位

本文档描述的是当前仓库里已经落地的 UAM 实现，而不是纯设计稿。

它回答四个问题：

1. UAM 当前已经接住了 GS 的哪些信息
2. 当前 SQLite 中有哪些正式对象
3. 当前应该怎样查询这些数据
4. 当前还没有做的部分是什么

当前文档基于 2026-04-12 这一次实现状态。

---

## 2. 当前结论

当前 UAM 已经不再是预留钩子，而是一个正式可用的 SQLite 资产契约层。

当前状态可以概括为：

- GS 已经可以把主机探活、L4 扫描事实、L7 服务识别结果写入 UAM
- UAM 已经具备 `Run / Host / Endpoint / Observation / Claim / Projection / ModuleResult` 完整骨架
- UAM 已经可以按 IP、端口、协议、tool、run 查询当前状态与历史观察
- UAM 已经可以输出一份面向人的综合报告
- gping 和专项扫描的执行器本体还没完成，但 UAM 契约入口已经存在

也就是说：

> 当前 UAM 已经足够作为 GS 的正式状态承接层使用。

---

## 3. 当前实现边界

### 3.1 已完成

- SQLite schema
- 基础 repository / store
- GS -> UAM ingest
- gping 契约入口
- module 契约入口
- Projection 刷新规则
- CLI 查询入口
- 文本综合报告入口

### 3.2 当前最重要的现实意义

当前 GS 扫描不再只是 stdout + JSON/YAML 文件输出。

它还会把有价值的资产事实推进到 UAM，使后续可以做：

- 按 IP / 端口查看当前资产状态
- 查看某个端点被哪些扫描事实支撑
- 查看某台主机被哪些 run 触达过
- 在未来接入 gping 时，直接对现有 Host / Endpoint 做确认、修订、待定、覆盖

### 3.3 还没有做

- gping CLI / 执行引擎本体
- HTTP/TLS/SSH 等专项扫描执行器本体
- 更复杂的聚合查询界面
- 更强的批量落库优化
- 更细的人工交互式确认工作流

---

## 4. 当前目录边界

当前 UAM 实现位于：

```text
internal/uam/
  domain/
  normalize/
  project/
  service/
  store/sqlite/
```

### 4.1 `domain/`

负责定义正式对象与枚举值：

- `Run`
- `Host`
- `Endpoint`
- `Observation`
- `Claim`
- `HostProjectionCurrent`
- `EndpointProjectionCurrent`
- `ModuleResult`

### 4.2 `store/sqlite/`

负责：

- 打开 SQLite
- 初始化 schema
- Upsert Host / Endpoint
- 写 Observation / Claim / ModuleResult
- 读写 Projection

### 4.3 `normalize/`

负责把不同生产者的输入归一成 Claim：

- `gs.go`
- `gping.go`
- `module.go`

### 4.4 `project/`

负责：

- Claim 优先级规则
- Projection 刷新规则
- `override > manual > observed > inferred`
- 同优先级下 `newer wins`

### 4.5 `service/`

负责把 ingest / query 做成稳定服务边界：

- `ingest_gs.go`
- `ingest_gping.go`
- `ingest_module.go`
- `query.go`
- `report.go`

---

## 5. 当前 SQLite 对象

当前已经落地的核心对象如下：

### 5.1 `runs`

表示一次工具执行。

当前 GS 写入：

- commandline
- targets
- profiles
- ports
- service_scan
- output 相关信息

### 5.2 `hosts`

当前阶段 Host 身份就是 IP。

### 5.3 `endpoints`

当前阶段 Endpoint 身份是：

- `host_id`
- `protocol`
- `port`

### 5.4 `observations`

当前真正承接了 GS 的原始事实。

GS 当前会写入三类 Observation：

1. 主机探活 Observation
2. L4 扫描 Observation
3. L7 enrichment Observation

### 5.5 `claims`

当前 GS 会产出：

- `network.reachability`
- `network.port_state`
- `network.discovery_method`
- `service.name`
- `service.product`
- `service.version`
- `service.info`
- `service.hostname`
- `service.os`
- `service.device`
- `service.banner`
- `service.cpes`

gping / module 契约入口还支持：

- `user.verification_state`
- `user.override_service_name`
- 其他后续 namespace

### 5.6 `host_projection_current`

当前保存：

- `current_reachability`
- `reachability_confidence`
- `verification_state`
- `last_seen_at`
- `source_tool`

### 5.7 `endpoint_projection_current`

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

### 5.8 `module_results`

当前已经可写，但当前仓库里还没有真正的专项扫描执行器在持续生产这层结果。

---

## 6. GS 当前是如何进入 UAM 的

当前不是只在最后导出画像时顺手存一下，而是沿扫描链多个阶段进入 UAM。

### 6.1 Run 初始化

扫描开始后，如果传入：

```bash
./goscan scan ... --uam-db uam.db
```

系统会先创建一条 `runs` 记录。

### 6.2 主机探活进入 UAM

当前主机探活成功后，UAM 会写入：

- 一条 Host Observation
- 一条 `network.reachability=reachable` Claim
- HostProjectionCurrent

当前主机探活方法包括：

- `icmp-echo`
- `tcp-syn-ping`

### 6.3 L4 扫描结果进入 UAM

当前 UAM 会接住 GS 的 L4 事实，而不是只接最终画像。

包括：

- `tcp-syn`
- `tcp-ack`
- `tcp-window`
- `udp`

对应结果包括：

- `open`
- `closed`
- `filtered`
- `unfiltered`
- `likely_open`

例如：

- `tcp-window=open` 会归一为 `network.port_state=likely_open`
- `tcp-ack=unfiltered` 会归一为 `network.port_state=unfiltered`

### 6.4 L7 服务识别进入 UAM

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

### 6.5 Projection 刷新

当前 Projection 严格由 Claim 推进，不允许 Observation 直接覆盖当前状态。

这意味着：

- L4 事实先进入 Observation
- 然后归一为 Claim
- 最后由 Claim 决定当前 Projection

---

## 7. 当前 GS 能进入 UAM 的信息清单

当前已经可以从 GS 承接以下信息：

### 7.1 Run 级

- commandline
- targets
- profiles
- ports
- service_scan
- output 相关元数据

### 7.2 Host 级

- ip
- first_seen_at
- last_seen_at
- reachability

### 7.3 Endpoint 级

- protocol
- port
- 当前端口状态
- discovery_method
- service 识别结果
- 结构化指纹字段

### 7.4 Observation 级

- raw_method
- raw_status
- route / action 类型
- request_summary
- response_summary
- error_text
- observed_at

### 7.5 Projection 级

- 当前主机状态
- 当前端点状态
- 当前服务视图
- 当前 banner / cpes / version 等

---

## 8. 当前查询能力

当前 CLI 已支持：

### 8.1 查看 runs

```bash
./goscan uam runs --db uam.db
```

也可以过滤：

```bash
./goscan uam runs --db uam.db --ip 192.168.1.10
./goscan uam runs --db uam.db --tool gs
```

### 8.2 查看当前主机视图

```bash
./goscan uam hosts --db uam.db
./goscan uam hosts --db uam.db --ip 192.168.1.10
```

### 8.3 查看当前端点视图

```bash
./goscan uam endpoints --db uam.db --ip 192.168.1.10
./goscan uam endpoints --db uam.db --ip 192.168.1.10 --port 443
./goscan uam endpoints --db uam.db --ip 192.168.1.10 --port 443 --protocol tcp
```

### 8.4 查看 Observation 历史

```bash
./goscan uam observations --db uam.db --ip 192.168.1.10
./goscan uam observations --db uam.db --ip 192.168.1.10 --port 443
./goscan uam observations --db uam.db --run-id <run_id>
```

### 8.5 输出综合报告

```bash
./goscan uam report --db uam.db --ip 192.168.1.10
./goscan uam report --db uam.db --ip 192.168.1.10 --port 443
./goscan uam report --db uam.db --ip 192.168.1.10 --port 443 --protocol tcp
```

---

## 9. 综合报告当前包含什么

当前 `uam report` 会输出一份偏人类阅读的文本报告，风格接近资产查看报告而不是 JSON dump。

当前会包含：

- Host 当前状态
- 最近触达该 IP 的 runs
- 当前 EndpointProjectionCurrent 视图
- Host 级 facts
- 每个端点的 Observation facts

也就是说，一份报告里既能看到：

- 当前结论
- 这些结论来自哪些扫描事实

这正是 UAM 当前和单纯画像文件最大的区别。

---

## 10. gping 当前与 UAM 的关系

当前仓库还没有真正的 gping 执行器，但 UAM 侧已经把核心契约准备好了。

当前已经支持：

- gping 创建 Run
- gping 写 Observation
- gping 写 Claim
- gping 推进 Projection
- `manual`
- `override`
- `verification_state`
- `override_service_name`

这意味着以后真正做 gping 时，不需要再重做 UAM 的数据层。

当前缺的是：

- gping 的执行路径
- gping 的 CLI
- gping 的 stack/raw/app 动作实现

---

## 11. 当前局限

当前 UAM 虽然已经可用，但还存在一些明确边界：

### 11.1 还不是大规模查询优化版本

当前已经能查，但还不是最终的高阶查询系统。

### 11.2 还没有专门的批处理写入优化

当前写入策略偏重正确性和结构完整性，后续还能继续优化吞吐。

### 11.3 还没有完整的人工工作流界面

虽然 `manual / override / verification_state` 契约存在，但还没有完整的交互工具层。

### 11.4 还没有专项扫描生产者

`module_results` 已经存在，但当前仓库还没有正式专项扫描器持续写入它。

---

## 12. 当前推荐使用方式

当前推荐把 UAM 当作：

1. GS 的正式状态库
2. 扫描细节回溯库
3. 后续 gping / 专项扫描的统一入口

一个典型工作流如下：

```bash
./goscan scan 192.168.1.10 --syn --ack --window -V -p 22,80,443 --uam-db uam.db
./goscan uam endpoints --db uam.db --ip 192.168.1.10
./goscan uam observations --db uam.db --ip 192.168.1.10 --port 443
./goscan uam report --db uam.db --ip 192.168.1.10
```

---

## 13. 当前阶段结论

如果只站在当前仓库和当前阶段目标来看，UAM 已经达到下面这个标准：

- 可以系统性承接 GS 的主要扫描事实
- 可以把这些事实沉淀为 Host / Endpoint 当前视图
- 可以支持未来 gping 与专项扫描继续接入
- 可以提供给人直接查询和阅读

所以当前的重点已经不再是“UAM 是否存在”，而是：

> 如何继续把查询体验、gping 执行器、专项扫描生产者建立在这套契约层之上。
