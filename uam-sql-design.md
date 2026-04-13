# docs/uam-sql-design.md

# UAM + SQLite 设计文档

## 1. 文档定位

本文档是 UAM（Unified Asset Model / 统一资产契约层）的正式设计与执行方案。

本文档用于指导快速实现 demo，但有一个严格前提：

> UAM 可以先做最小实现，但不允许在对象边界、状态语义、写入路径、扩展方式上留下结构性地雷。

因此，本文档不允许出现以下思路：

- “先做一个简单结果表，后面再拆”
- “先把专项字段塞进核心资产表，后面再整理”
- “先不做 Claim，直接把结果写成最终状态”
- “先用 JSON 大对象顶着，后面再建关系模型”

这些做法全部禁止。

---

## 2. UAM 的正式定义

> UAM 是 GS、gping 与后续专项扫描之间的统一资产契约层。它以 Host 和 Endpoint 为身份骨架，以 Observation 记录原始观察，以 Claim 归一资产断言，以 Projection 维护当前资产视图，以 ModuleResult 承载专项扩展结果。

---

## 3. UAM 要解决的问题

UAM 必须同时解决以下问题：

### 3.1 统一资产身份
GS、gping、专项扫描都可能观察到同一个对象。  
UAM 必须统一：

- 哪些结果属于同一个 Host
- 哪些结果属于同一个 Endpoint

---

### 3.2 统一观察语言
GS 产出扫描事实。  
gping 产出动作证据。  
专项扫描产出模块结果。  
UAM 必须接住这些不同性质的输入。

---

### 3.3 统一断言语言
不同工具看到的结果不同，但最终都必须能落到统一的资产断言语言上，例如：

- 端口状态
- 服务识别
- 主机可达性
- 人工确认状态

---

### 3.4 维护当前资产视图
不能只有历史记录。  
必须能快速回答：

- 当前哪些端点是开放的
- 当前服务是什么
- 当前哪些端点待确认
- 当前哪些适合继续深扫

---

### 3.5 承载专项深结果而不污染核心资产模型
后续专项扫描一定会产生大量高度专用字段。  
UAM 必须允许这些字段被持久化，但不能把核心资产模型拖垮。

---

## 4. 核心设计原则

### 原则 1：五层对象模型必须完整存在
UAM 必须由以下五层组成：

1. Identity
2. Observation
3. Claim
4. Projection
5. Extension

禁止省略其中任意一层后再用“后面补”来解释。

---

### 原则 2：Observation 不等于 Claim
Observation 记录“发生了什么”。  
Claim 记录“这意味着什么资产断言”。

二者必须分离。

---

### 原则 3：Projection 不等于历史真相
Projection 是当前视图，不是历史日志。  
它必须由 Claim 推导，而不是由最后一次 Observation 直接覆盖。

---

### 原则 4：专项深结果进入扩展层
专项扫描只允许把通用结论推进到 Claim / Projection。  
模块专属深字段必须进入 ModuleResult。

---

### 原则 5：所有当前状态都必须可追溯
任何一个当前状态都必须能追溯到：

- 来自哪个 Run
- 来自哪条 Observation
- 来自哪条 Claim
- 来自哪个 Tool / Module

---

## 5. 领域对象总览

当前阶段的最小完整对象集合如下：

1. `Run`
2. `Host`
3. `Endpoint`
4. `Observation`
5. `Claim`
6. `HostProjectionCurrent`
7. `EndpointProjectionCurrent`
8. `ModuleResult`

---

## 6. 对象定义

## 6.1 Run

### 作用
表示一次工具运行。

### 来源
- 一次 GS 扫描
- 一次 gping 执行
- 一次专项模块运行

### 最小字段
- `run_id`
- `tool`
- `module_name`
- `commandline`
- `started_at`
- `finished_at`
- `targets_json`
- `profiles_json`
- `ports_json`
- `service_scan`
- `extra_json`

### 原因
Run 是全链路追溯的根对象。  
GS 当前已经有元数据，gping 和专项扫描未来也必须有统一来源登记。

---

## 6.2 Host

### 作用
表示主机身份。

### 当前阶段身份定义
- `ip`

### 最小字段
- `host_id`
- `ip`
- `first_seen_at`
- `last_seen_at`

### 原因
当前 GS 的主发现对象就是 IP。  
当前阶段不引入更复杂身份，以保持最小且稳定。

---

## 6.3 Endpoint

### 作用
表示主机上的一个传输端点。

### 当前阶段身份定义
- `host_id`
- `protocol`
- `port`

### 最小字段
- `endpoint_id`
- `host_id`
- `protocol`
- `port`
- `first_seen_at`
- `last_seen_at`

### 原因
GS 当前的核心资产粒度就是端点画像。  
gping 和专项扫描也普遍以端点为主要动作对象。

---

## 6.4 Observation

### 作用
记录一次具体观察。

### 最小字段
- `observation_id`
- `run_id`
- `tool`
- `module_name`
- `host_id`
- `endpoint_id`
- `route_used`
- `action_type`
- `raw_method`
- `raw_status`
- `request_summary`
- `response_summary`
- `rtt_ms`
- `error_text`
- `observed_at`
- `extra_json`

### 原因
Observation 是统一接入层：

- GS 的扫描结果先变成 Observation
- gping 的动作执行先变成 Observation
- 专项扫描的模块观察先变成 Observation

Observation 只负责记录事实，不负责直接定义最终资产状态。

---

## 6.5 Claim

### 作用
从 Observation 归一出来的资产断言。

### 最小字段
- `claim_id`
- `observation_id`
- `subject_type`
- `subject_id`
- `namespace`
- `name`
- `value_text`
- `value_json`
- `confidence`
- `assertion_mode`
- `claimed_at`

### 原因
Claim 是 UAM 的统一资产语言。  
Projection 只能从 Claim 刷新，不能直接吃 Observation。

---

## 6.6 HostProjectionCurrent

### 作用
保存当前主机视图。

### 最小字段
- `host_id`
- `current_reachability`
- `reachability_confidence`
- `verification_state`
- `last_seen_at`
- `last_claim_id`
- `last_observation_id`
- `source_tool`

### 原因
主机可达性与主机确认状态必须单独可查。  
HostProjectionCurrent 不能省略。

---

## 6.7 EndpointProjectionCurrent

### 作用
保存当前端点视图。

### 最小字段
- `endpoint_id`
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
- `last_claim_id`
- `last_observation_id`
- `source_tool`

### 原因
这是当前阶段最重要的资产视图，也是 GS 当前成果最直接的持久化承接点。

---

## 6.8 ModuleResult

### 作用
承载专项扫描或深度模块的扩展结果。

### 最小字段
- `module_result_id`
- `run_id`
- `observation_id`
- `subject_type`
- `subject_id`
- `module_name`
- `schema_version`
- `data_json`
- `created_at`

### 原因
专项结果必须可存，但不得进入核心 Projection。

---

## 7. 状态语言与枚举规范

## 7.1 Tool
允许值：
- `gs`
- `gping`
- `module`

---

## 7.2 Route Used
允许值：
- `stack`
- `raw`
- `app`
- `null`

说明：
- gping 使用 `stack/raw/app`
- GS 建议使用 `null`
- 专项扫描按实际情况填写

---

## 7.3 Action Type
允许值：
- `reach`
- `probe`
- `handshake`
- `request`
- `inject`
- `scan`
- `collect`

说明：
- GS 统一使用 `scan`
- gping 使用 `reach/probe/handshake/request/inject`
- 专项扫描可使用 `collect`

---

## 7.4 Assertion Mode
允许值：
- `observed`
- `inferred`
- `manual`
- `override`

说明：
- GS 多数是 `observed` / `inferred`
- gping 自动验证一般为 `observed`
- gping 人工确认使用 `manual`
- 用户强制修正使用 `override`

---

## 7.5 Verification State
允许值：
- `none`
- `pending`
- `confirmed`
- `overridden`

说明：
此状态只表示人工/定向确认程度，不直接表示网络状态。

---

## 7.6 Endpoint Port State
允许值：
- `open`
- `closed`
- `filtered`
- `unfiltered`
- `likely_open`
- `unknown`

---

## 7.7 Host Reachability
允许值：
- `reachable`
- `unreachable`
- `unknown`

---

## 8. Claim 语义规范

Claim 使用 `namespace + name` 二元标识。

### 推荐 namespace
- `network`
- `service`
- `http`
- `tls`
- `ssh`
- `user`

### 推荐核心 claims

#### Host 级
- `network.reachability`

#### Endpoint 级
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

#### 用户 / 定向确认
- `user.verification_state`
- `user.note`
- `user.override_service_name`

#### 后续常见扩展
- `http.status_code`
- `http.title`
- `tls.handshake`
- `tls.cert_issuer`

---

### Claim 值规则

#### `value_text`
用于：
- 简单枚举值
- 字符串值
- 单值数字的文本表达

例如：
- `open`
- `http`
- `nginx`
- `403`

#### `value_json`
用于：
- 列表
- 复杂对象
- 多字段结构

例如：
- `cpes`
- 证书信息
- 复杂解析结果

规则：
- 简单值优先写 `value_text`
- 复杂值写 `value_json`
- 至少填一个



## 9. SQLite DDL

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  tool TEXT NOT NULL CHECK (tool IN ('gs', 'gping', 'module')),
  module_name TEXT NOT NULL,
  commandline TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  targets_json TEXT,
  profiles_json TEXT,
  ports_json TEXT,
  service_scan INTEGER NOT NULL DEFAULT 0 CHECK (service_scan IN (0,1)),
  extra_json TEXT
);

CREATE TABLE hosts (
  host_id TEXT PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE endpoints (
  endpoint_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port >= 0 AND port <= 65535),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(host_id, protocol, port),
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE
);

CREATE TABLE observations (
  observation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  tool TEXT NOT NULL CHECK (tool IN ('gs', 'gping', 'module')),
  module_name TEXT NOT NULL,
  host_id TEXT NOT NULL,
  endpoint_id TEXT,
  route_used TEXT CHECK (route_used IN ('stack', 'raw', 'app') OR route_used IS NULL),
  action_type TEXT NOT NULL CHECK (
    action_type IN ('reach', 'probe', 'handshake', 'request', 'inject', 'scan', 'collect')
  ),
  raw_method TEXT,
  raw_status TEXT,
  request_summary TEXT,
  response_summary TEXT,
  rtt_ms REAL,
  error_text TEXT,
  observed_at TEXT NOT NULL,
  extra_json TEXT,
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE
);

CREATE TABLE claims (
  claim_id TEXT PRIMARY KEY,
  observation_id TEXT NOT NULL,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('host', 'endpoint')),
  subject_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  value_text TEXT,
  value_json TEXT,
  confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
  assertion_mode TEXT NOT NULL CHECK (
    assertion_mode IN ('observed', 'inferred', 'manual', 'override')
  ),
  claimed_at TEXT NOT NULL,
  FOREIGN KEY (observation_id) REFERENCES observations(observation_id) ON DELETE CASCADE
);

CREATE TABLE host_projection_current (
  host_id TEXT PRIMARY KEY,
  current_reachability TEXT CHECK (
    current_reachability IN ('reachable', 'unreachable', 'unknown')
  ),
  reachability_confidence INTEGER CHECK (
    reachability_confidence >= 0 AND reachability_confidence <= 100
  ),
  verification_state TEXT NOT NULL DEFAULT 'none' CHECK (
    verification_state IN ('none', 'pending', 'confirmed', 'overridden')
  ),
  last_seen_at TEXT,
  last_claim_id TEXT,
  last_observation_id TEXT,
  source_tool TEXT CHECK (source_tool IN ('gs', 'gping', 'module')),
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
  FOREIGN KEY (last_claim_id) REFERENCES claims(claim_id) ON DELETE SET NULL,
  FOREIGN KEY (last_observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE TABLE endpoint_projection_current (
  endpoint_id TEXT PRIMARY KEY,
  current_port_state TEXT CHECK (
    current_port_state IN ('open', 'closed', 'filtered', 'unfiltered', 'likely_open', 'unknown')
  ),
  port_state_confidence INTEGER CHECK (
    port_state_confidence >= 0 AND port_state_confidence <= 100
  ),
  current_service TEXT,
  current_product TEXT,
  current_version TEXT,
  current_info TEXT,
  current_hostname TEXT,
  current_os TEXT,
  current_device TEXT,
  current_banner TEXT,
  current_cpes_json TEXT,
  verification_state TEXT NOT NULL DEFAULT 'none' CHECK (
    verification_state IN ('none', 'pending', 'confirmed', 'overridden')
  ),
  last_seen_at TEXT,
  last_claim_id TEXT,
  last_observation_id TEXT,
  source_tool TEXT CHECK (source_tool IN ('gs', 'gping', 'module')),
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
  FOREIGN KEY (last_claim_id) REFERENCES claims(claim_id) ON DELETE SET NULL,
  FOREIGN KEY (last_observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE TABLE module_results (
  module_result_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  observation_id TEXT,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('host', 'endpoint')),
  subject_id TEXT NOT NULL,
  module_name TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
  FOREIGN KEY (observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE INDEX idx_hosts_ip ON hosts(ip);

CREATE INDEX idx_endpoints_host_protocol_port
ON endpoints(host_id, protocol, port);

CREATE INDEX idx_observations_run ON observations(run_id);
CREATE INDEX idx_observations_host ON observations(host_id);
CREATE INDEX idx_observations_endpoint ON observations(endpoint_id);
CREATE INDEX idx_observations_tool_module_time
ON observations(tool, module_name, observed_at);

CREATE INDEX idx_claims_observation ON claims(observation_id);
CREATE INDEX idx_claims_subject ON claims(subject_type, subject_id);
CREATE INDEX idx_claims_ns_name ON claims(namespace, name);
CREATE INDEX idx_claims_subject_time
ON claims(subject_type, subject_id, claimed_at);

CREATE INDEX idx_module_results_subject
ON module_results(subject_type, subject_id);
CREATE INDEX idx_module_results_module
ON module_results(module_name, created_at);
10. 推荐视图
CREATE VIEW v_endpoint_assets AS
SELECT
  e.endpoint_id,
  h.ip,
  e.protocol,
  e.port,
  ep.current_port_state,
  ep.port_state_confidence,
  ep.current_service,
  ep.current_product,
  ep.current_version,
  ep.current_info,
  ep.current_hostname,
  ep.current_os,
  ep.current_device,
  ep.current_banner,
  ep.current_cpes_json,
  ep.verification_state,
  ep.last_seen_at,
  ep.source_tool
FROM endpoints e
JOIN hosts h ON h.host_id = e.host_id
LEFT JOIN endpoint_projection_current ep ON ep.endpoint_id = e.endpoint_id;

CREATE VIEW v_host_assets AS
SELECT
  h.host_id,
  h.ip,
  hp.current_reachability,
  hp.reachability_confidence,
  hp.verification_state,
  hp.last_seen_at,
  hp.source_tool
FROM hosts h
LEFT JOIN host_projection_current hp ON hp.host_id = h.host_id;

CREATE VIEW v_recent_observations AS
SELECT
  o.observation_id,
  o.tool,
  o.module_name,
  h.ip,
  e.protocol,
  e.port,
  o.route_used,
  o.action_type,
  o.raw_method,
  o.raw_status,
  o.request_summary,
  o.response_summary,
  o.rtt_ms,
  o.error_text,
  o.observed_at
FROM observations o
JOIN hosts h ON h.host_id = o.host_id
LEFT JOIN endpoints e ON e.endpoint_id = o.endpoint_id;
```
11. GS 接入方案
11.1 GS 进入 UAM 的目标

GS 当前已经接近收紧，因此 UAM 必须优先无损承接 GS 中所有有价值的资产成果。

GS 当前有价值的对象包括：

IP
Port
Protocol
Method
State
Service
Product
Version
Info
Hostname
OS
Device
CPEs
Banner
Run metadata
Portrait metadata

这些全部都应进入 UAM。

11.2 GS 写入流程
步骤 1：创建 Run

将本次扫描命令与元数据写入 runs。

步骤 2：Upsert Host / Endpoint

对于每条扫描结果：

按 IP upsert hosts
按 (host_id, protocol, port) upsert endpoints
步骤 3：写 Observation

每条 ScanResult 写入 observations：

推荐映射：

tool = 'gs'
module_name = 'gs-l4l7'
action_type = 'scan'
route_used = NULL
raw_method = ScanResult.Method
raw_status = ScanResult.State
response_summary = 可由 service/banner 摘要构成
extra_json = 其余原始字段
步骤 4：生成 Claim

从 Observation 归一出 Claim。

L4 类 Claims
network.port_state
network.discovery_method
L7 类 Claims
service.name
service.product
service.version
service.info
service.hostname
service.os
service.device
service.banner
service.cpes
步骤 5：刷新 Projection

用 Claim 刷新：

host_projection_current
endpoint_projection_current
11.3 为什么 GS 必须这样接入
为了 gping：gping 后续要针对 GS 发现的资产做定向验证。
为了 专项扫描：专项扫描通常从已知开放端点和初步服务识别出发。
为了 UAM：GS 的结果必须从“扫描输出”升级为“系统状态输入”。
12. gping 接入方案
12.1 gping 的前提

gping 不是 GS 的附庸。
gping 可以独立使用，也可以依赖 UAM 增强。

因此 UAM 必须原生支持 gping 的结果进入。

12.2 gping 写入流程
步骤 1：创建 Run
tool = 'gping'
module_name = 'gping'
commandline 填 CLI
targets_json 填目标
extra_json 可填上下文摘要
步骤 2：Upsert Host / Endpoint

和 GS 一样：

Host 由 IP 确定
Endpoint 由 (ip, protocol, port) 确定
步骤 3：写 Observation

记录本次动作：

route_used = stack/raw/app
action_type = reach/probe/handshake/request/inject
raw_method = 动作名称
raw_status = success/fail/timeout/...
request_summary
response_summary
rtt_ms
error_text
extra_json
步骤 4：生成 Claim

例如：

TCP connect 成功 -> network.port_state = open
HTTP 403 -> http.status_code = 403
TLS 握手成功 -> tls.handshake = success
人工确认服务 -> service.name = http + assertion_mode = manual
人工标记待定 -> user.verification_state = pending
步骤 5：刷新 Projection

只推进通用资产语言：

端口状态
服务字段
verification_state
少量通用高价值信息

深字段不直接写 Projection。

12.3 为什么必须为 gping 这样设计
为了 GS：gping 是 GS 发现结果的确认工具。
为了 专项扫描：gping 会成为很多专项场景下的手工或半自动验证补刀工具。
为了 UAM：manual / override / pending 这些能力不能后补，必须从第一天进入正式模型。
13. 专项扫描接入方案
13.1 接入规则

专项扫描必须遵守三条规则：

必须写 Observation
能抽通用结论时必须写 Claim
专属深字段必须写 ModuleResult
13.2 示例：HTTP 专项
Observation
请求摘要
响应摘要
RTT
错误信息
Claim
service.name = http
http.status_code = 200/403/...
ModuleResult
title
headers
favicon hash
redirect chain
body digest
13.3 示例：TLS 专项
Observation
握手摘要
协商摘要
RTT
Claim
tls.handshake = success
通用服务判断
ModuleResult
issuer
subject
SAN
ALPN
version
cipher
13.4 为什么必须这样做
为了 gping：状态语言必须统一。
为了 GS：专项扫描必须能接上现有资产端点。
为了 UAM：专项模块不能反向污染核心资产模型。
14. Projection 刷新规则

Projection 不能由 Observation 直接覆盖，必须由 Claim 推进。

14.1 HostProjectionCurrent
可推进字段
network.reachability
优先级规则
override > manual > observed > inferred
同优先级下 newer wins
verification_state
默认 none
人工确认 -> confirmed
人工待定 -> pending
强制修正 -> overridden
14.2 EndpointProjectionCurrent
可推进字段
network.port_state
service.name
service.product
service.version
service.info
service.hostname
service.os
service.device
service.banner
service.cpes
user.verification_state
优先级规则
override > manual > observed > inferred
同优先级下 newer wins
冲突规则
只更新当前投影
不删除历史 Claim
14.3 为什么必须这样做
为了 gping：人工确认必须高于自动发现
为了 专项扫描：深扫结论不能无脑覆盖全部状态
为了 GS：GS 是入口，不是永恒最终裁判
15. ModuleResult 设计规则
15.1 ModuleResult 是唯一专项深字段承载层

任何模块专属复杂结果都必须进入 module_results.data_json。

禁止把此类字段直接塞进 endpoint_projection_current。

15.2 ModuleResult 的强约束

每条结果必须带：

module_name
schema_version
subject_type
subject_id
run_id
created_at
15.3 合法 TODO
合法 TODO 1

未来新增更多 claim namespace，例如：

rdp
mqtt
custom_proto

前提是 Claim 机制本身已经完整存在。

合法 TODO 2

未来细化某个模块的 data_json 内部 schema。
前提是 ModuleResult 这一层已经正式存在。

16. 明确禁止的实现方式
禁止 1：禁止做“最后结果表”

例如：

assets(ip, port, state, service, banner, updated_at)

这是错误实现。

禁止 2：禁止用 JSON 替代核心关系模型

例如：

只做 observations(data_json)
只做 assets(data_json)

这是错误实现。

禁止 3：禁止把专项字段塞进核心 Projection

例如：

http_title
tls_issuer
ssh_kex_algorithms

这些不允许直接成为核心 Projection 字段。

禁止 4：禁止 Observation 直接驱动最终状态

必须经过 Claim。

禁止 5：禁止省略 HostProjectionCurrent

HostProjectionCurrent 不能因为“当前重点在端点”而被省掉。

17. 执行顺序
阶段 1：实现 schema 与基础仓储

必须先落：

DDL
外键
索引
视图
基础 CRUD / upsert
阶段 2：实现 Identity Upsert

实现：

ensureHost(ip)
ensureEndpoint(ip, protocol, port)
阶段 3：实现 GS ingest

必须完成：

Run 写入
Observation 写入
Claim 生成
Projection 刷新
阶段 4：实现 Projection 刷新器

规则必须以 Claim 为唯一输入。

阶段 5：实现 ModuleResult

即使当前没有专项扫描生产者，也必须落好这一层。

阶段 6：实现 gping 契约入口

即使 gping 还没完整写完，UAM 侧也必须预留：

Run 创建
Observation 写入
Claim 接口
Projection 刷新
manual / override 写入入口
18. 推荐 Go 层边界

建议按下列组件实现：

18.1 Identity Repository

负责：

ensure host
ensure endpoint
查询 host / endpoint
18.2 Run Repository

负责：

create run
finish run
查询 run
18.3 Observation Repository

负责：

create observation
查询 observation
18.4 Claim Repository

负责：

insert claims
查询 claims
18.5 Projection Repository

负责：

refresh host projection
refresh endpoint projection
查询 current projection
18.6 ModuleResult Repository

负责：

insert module result
查询 module result
18.7 Normalizer

负责：

GS Observation -> Claims
gping Observation -> Claims
module Observation -> Claims

说明：
Normalizer 必须是独立层，不能把归一逻辑散落到 repository 中。

19. 推荐目录边界
internal/uam/
  domain/
    run.go
    host.go
    endpoint.go
    observation.go
    claim.go
    projection.go
    module_result.go

  store/sqlite/
    migrations/
    run_repo.go
    identity_repo.go
    observation_repo.go
    claim_repo.go
    projection_repo.go
    module_result_repo.go

  normalize/
    gs.go
    gping.go
    module.go

  project/
    host_projection.go
    endpoint_projection.go

  service/
    ingest_gs.go
    ingest_gping.go
    ingest_module.go
20. 最终执行说明

UAM 的目标不是保存扫描结果，而是把 GS 的高速发现、gping 的定向验证、后续专项扫描的深结果，统一沉淀为可查询、可追溯、可确认、可扩展的资产状态系统。

当前阶段的执行必须以“最小契约完整成立”为目标，而不是以“先跑通几个表”为目标。

因此，本设计从第一天起就同时具备：

身份层
观察层
断言层
当前投影层
专项扩展层

GS 当前已经接近收紧，因此 UAM 必须优先无损承接 GS 中所有有价值的资产信息；同时，为了 gping 的人工确认能力与专项扫描的独立扩展能力，UAM 不能退化为 GS 专用结果库。

任何不经过 Claim 的直接状态写入、任何把专项字段塞进核心资产表的做法、任何用 JSON 代替核心关系模型的做法，都属于违反本设计意志的错误实现。