
# gping 设计补充方案

> 当前落地实现说明请配合阅读 `doc/gping.md`。本文档仍然主要承担设计补充与边界讨论角色。

## 1. 文档目的

本文档用于补充当前项目文档中对 **gping** 的定义、边界与落地方向，明确 gping 在整个体系中的正式定位，并给出其执行引擎、三大路线、UAM 对接方式、模板化能力及验证闭环。

本文档解决三个核心问题：

1. gping 如何完整补足当前项目中已经提出但尚未正式展开的能力。
2. gping 如何天然对接 UAM，用于资产确认、修订、待定与覆盖。
3. gping 如何同时保持独立工具属性，具备类似 Nping 的自由探测与模板化扩展能力。

---

## 2. gping 的正式定位

gping 不是 GS 的一个扫描模式，也不是 GS 的后处理器。  
gping 应被定义为：

> 一个面向目标行为验证与人工确认的多路线探测引擎。

它同时具有两个同等重要的身份：

### 2.1 独立工具身份

gping 必须能够脱离 UAM 独立运行，像 Nping 一样支持：

- 单目标动作
- 包级参数控制
- 畸形包与实验包
- 协议级握手
- 应用级请求
- 模板化动作链
- 可组合验证流程

这意味着：**没有 UAM，gping 也必须成立。**

### 2.2 UAM 确认器身份

gping 也必须能够读取 UAM 当前资产视图，对已有 Host / Endpoint 做：

- 确认
- 修订
- 待定
- 覆盖
- 追加上下文信息

这意味着：**有 UAM 时，gping 不只是“打一枪看看”，而是资产确认闭环的一部分。**

---

## 3. gping 的设计原则

### 3.1 统一的是动作生命周期，不是发送实现

raw、stack、app 三条路线内部实现可以完全不同，但必须共享统一工作流：

```text
Resolve -> Plan -> Prepare -> Execute -> Interpret -> Emit
````

统一的是：

* 目标如何解析
* 动作如何构造
* 结果如何解释
* 输出如何写入 UAM

不统一的是：

* 实际发包方式
* 实际收包方式
* 实际协议处理逻辑

---

### 3.2 统一的是输出语言，不是内部机制

三条路线都必须能产出统一的结果语言：

* Observation 事实
* Claims 断言
* Assertion 意图

这样 UAM 才能天然接住 gping 的结果，而不会出现每条路线各说各话。

---

### 3.3 gping 是人工驱动增强，不是再做一遍 GS

GS 的职责是：

* 自动发现
* 初步判断
* 大规模覆盖
* 高吞吐扫描

gping 的职责是：

* 围绕怀疑点做定向验证
* 围绕确认点做进一步探测
* 围绕资产上下文做人工增强
* 将结果沉淀为 UAM 中的观察与断言

因此 gping 必须是 **manual-first**，不是 blind-auto。

---

## 4. gping 的总体结构

gping 应拆成五层：

### 4.1 Target Resolver

负责统一解析目标来源，支持：

* 字面目标（IP / Port / Protocol / URL / Host / SNI）
* UAM 目标（Host / Endpoint / Query 结果）

输出统一的 `TargetContext`。

---

### 4.2 Planner

负责把用户参数、模板、UAM 上下文编译成一个或多个 `ActionUnit`。

一个 `ActionUnit` 是最小执行单元，它必须对应 **一条 Observation**。

例如一次 HTTPS 确认可能展开为：

1. stack / tcp-connect
2. stack / tls-handshake
3. app / http-head
4. app / http-get

这是一个 workflow，但不是一条 observation，而是四条 observation。

---

### 4.3 Route Executors

三条路线都只是执行器：

* RawExecutor
* StackExecutor
* AppExecutor

它们只负责：

* 如何准备
* 如何执行
* 如何产生证据

它们不直接决定最终资产结论。

---

### 4.4 Interpreter

解释层负责把路线证据转换成：

* Observation 字段
* 标准化 Claims
* 人工意图 Claims

这是 gping 与 UAM 契约对接的关键层。

---

### 4.5 Sinks

输出层支持：

* 终端输出
* JSON 输出
* UAM 写入
* 后续证据文件输出

---

## 5. 统一生命周期

### 5.1 Resolve

统一解析目标来源。

支持的输入形式包括：

* `--ip 1.2.3.4 --port 443`
* `--url https://1.2.3.4/health`
* `--host example.internal --port 443`
* `--uam-endpoint <id>`
* `--uam-query '<selector>'`

解析后形成统一目标上下文：

* IP
* Protocol
* Port
* Hostname / Host Header
* SNI
* URL
* 来源信息
* UAM 当前上下文

---

### 5.2 Plan

Planner 负责把显式参数、模板、UAM 上下文编译成结构化动作。

它必须支持：

* 显式 route
* 自动 route 选择
* 单动作
* 多动作链
* 模板展开
* 人工确认意图

例如：

* `--route raw --tcp-flags syn,fin`
* `--template http/envoy-confirm`
* `--assert confirmed`
* `--override-service envoy`

Planner 的输出是若干 `ActionUnit`。

---

### 5.3 Prepare

各路线在执行前做准备。

#### raw

* 选择出口
* 获取源地址
* 获取下一跳与 MAC
* 建立 capture
* 生成 matcher / BPF

#### stack

* 构建 dialer
* 构建 tls config
* 配置 banner read / write

#### app

* 构建 http transport
* 配置 header / path / redirect / host / sni
* 配置应用层 matcher

---

### 5.4 Execute

执行动作并返回统一的 `RouteEvidence`。

此阶段只负责产出证据，不直接产出最终资产结论。

---

### 5.5 Interpret

将 `RouteEvidence` 转换为：

* `route_used`
* `action_type`
* `raw_method`
* `raw_status`
* `request_summary`
* `response_summary`
* `rtt_ms`
* `error_text`
* `claims`

解释层必须显式区分：

1. 观测事实
2. 标准化断言
3. 操作者意图

---

### 5.6 Emit

将解释后的结果输出到：

* 终端
* JSON
* UAM

如果一个 workflow 展开出多个 `ActionUnit`，则每个 `ActionUnit` 都独立写入一条 observation，但共享同一个 gping run。

---

## 6. gping 的统一结果契约

为了天然契合当前项目中的 `GPingObservationInput`，gping 应当形成统一输出模型。

### 6.1 统一执行报告

建议 gping 内部统一输出一个 `ExecutionReport`，其中包含：

* IP
* Protocol
* Port
* RouteUsed
* ActionType
* RawMethod
* RawStatus
* RequestSummary
* ResponseSummary
* RTTMs
* ErrorText
* Claims

这组字段必须能够一对一映射到 `GPingObservationInput`。

---

### 6.2 三层结果语义

#### 第一层：Observation 事实

表示这次动作真实发生了什么，例如：

* 使用了哪条 route
* 执行了什么 method
* 收到了什么响应
* RTT 多久
* 是否超时 / 报错

#### 第二层：Claims 断言

表示从这次动作中提炼出的资产语义，例如：

* `network.port_state=open`
* `service.name=https`
* `service.product=envoy`
* `service.version=1.27.x`
* `http.title=Admin`
* `tls.subject=example.com`

#### 第三层：Assertion 意图

表示操作者基于结果做出的确认行为，例如：

* `verification_state=confirmed`
* `verification_state=pending`
* `override_service_name=envoy`

这三层必须严格分离。

---

## 7. 三大路线的正式定义

---

## 7.1 Raw Route

### 定位

Raw Route 是 gping 中最接近 Nping 的核心路线，用于进行：

* 原始报文控制
* 畸形包实验
* L3 / L4 精确探测
* 低层响应观察

### 能力范围

必须支持：

* 自定义 TCP Flags
* 自定义 ICMP Type / Code
* TTL / Window / Checksum / Fragment
* Payload 自定义
* 精确超时与重试控制
* BPF / 过滤器 / 响应匹配
* 单包、多包、序列化实验

### 适合的动作

例如：

* `tcp-syn`
* `tcp-ack`
* `tcp-fin`
* `tcp-xmas`
* `icmp-echo-raw`
* `udp-probe-raw`

### 输出特征

raw route 输出要尽量保真，例如：

* `route_used = raw`
* `action_type = probe`
* `raw_method = tcp-syn`
* `raw_status = syn-ack`
* `raw_status = rst-ack`
* `raw_status = timeout`

### 与 UAM 的关系

raw route 非常适合生成网络层 claims，例如：

* `network.port_state=open`
* `network.port_state=closed`
* `network.port_state=filtered`
* `network.reachability=reachable`
* `network.reachability=unreachable`

raw route 通常不直接承担应用层产品确认。

---

## 7.2 Stack Route

### 定位

Stack Route 走操作系统协议栈，代表真实通信行为验证。

### 能力范围

必须支持：

* ICMP echo
* TCP connect
* UDP send/recv
* TLS handshake
* 轻量 banner 读取
* 少量 payload write/read

### 适合的动作

例如：

* `icmp-echo`
* `tcp-connect`
* `udp-connect`
* `tls-handshake`
* `banner-read`

### 输出特征

例如：

* `route_used = stack`
* `action_type = probe`
* `raw_method = tcp-connect`
* `raw_status = open`
* `raw_status = refused`
* `raw_status = timeout`

或：

* `route_used = stack`
* `action_type = handshake`
* `raw_method = tls-handshake`
* `raw_status = success`

### 与 UAM 的关系

stack route 非常适合形成：

* `network.port_state`
* `service.banner`
* `service.name`
* TLS 结构化信息
* 轻量的服务产品/版本提示

它是 UAM 中“连通性确认”和“轻量协议确认”的核心路线。

---

## 7.3 App Route

### 定位

App Route 面向高层协议语义与人工确认。

它关注的不是“端口开不开”，而是“这个端口实际提供什么应用行为”。

### 能力范围

必须支持：

* HTTP / HTTPS 请求
* DNS 查询
* Host / SNI / Header / Path / Body 可控
* Redirect 策略控制
* TLS 忽略校验
* 响应摘要提取
* 模板化动作链

### 适合的动作

例如：

* `http-head`
* `http-get`
* `http-post`
* `dns-query`

### 输出特征

例如：

* `route_used = app`
* `action_type = request`
* `raw_method = http-get`
* `raw_status = 200 OK`
* `raw_status = 403 Forbidden`

同时记录：

* `request_summary`
* `response_summary`

### 与 UAM 的关系

app route 最适合形成：

* `service.name`
* `service.product`
* `service.version`
* `service.hostname`
* `http.title`
* `http.server`
* `http.location`
* `tls.subject`
* `tls.san`
* `user.verification_state`
* `user.override_service_name`

---

## 8. gping 与 UAM 的正式接缝

当前项目中，UAM 已经具备：

* gping Run 写入
* gping Observation 写入
* gping Claim 写入
* Projection 推进
* `verification_state`
* `override_service_name`

因此，gping 不应该再造一套独立的资产模型。
最正确的做法是：

> gping 内部统一产出 `ExecutionReport`，并将其直接映射到 `GPingObservationInput`。

---

### 8.1 接缝原则

每个最小动作单元必须能直接形成：

* 一条 Observation
* 一组 Claims
* 可选的人工 Assertion

这意味着 gping 的执行结果天然可被 `GPingIngester` 接入。

---

### 8.2 Claims 的来源

建议 Claims 分为三类提取器：

#### NetworkClaimExtractor

负责提取：

* `network.reachability`
* `network.port_state`

#### ServiceClaimExtractor

负责提取：

* `service.name`
* `service.product`
* `service.version`
* `service.banner`
* `service.hostname`
* `http.title`
* `http.server`
* `tls.subject`

#### AssertionClaimExtractor

负责提取：

* `user.verification_state`
* `user.override_service_name`

这三类逻辑不能下沉到三条路线执行器内部。

---

## 9. 模板系统设计

这是 gping 与 GS 职责分离的关键点。

### 9.1 模板不是自动扫描器

模板不是为了替代 GS，不是为了默认自动扫一遍协议。
模板应该定义为：

> 人工选择的、可复用的动作链与提取规则。

模板的意义在于：

* 固化常见确认剧本
* 缩短重复操作成本
* 保留人工控制权
* 保证结果可解释

---

### 9.2 模板能力要求

模板至少应支持：

#### 1. 动作链复用

例如一个 HTTPS enrich 模板可以包含：

1. `stack/tcp-connect`
2. `stack/tls-handshake`
3. `app/http-head /`
4. `app/http-get /health`

#### 2. 变量化

模板变量至少包括：

* host
* sni
* path
* headers
* expected code
* expected keyword
* tls verify mode

#### 3. 提取规则

模板应定义如何从响应中提取：

* server header
* title
* body keyword
* redirect location
* cert subject / SAN
* content-length

并把这些内容转成：

* summaries
* claims
* optional confirm suggestions

---

### 9.3 模板的边界

模板不应默认自动对所有 UAM 资产执行。
否则它就退化成“另一种 GS”。

正确方式应为：

* 操作者显式选择模板
* 模板针对具体怀疑方向
* 模板输出更深的上下文证据
* 是否确认 / 待定 / 覆盖由操作者决定

---

## 10. 建议的模板类型

### 10.1 基础协议模板

例如：

* `tcp/basic-open-check`
* `tls/basic-handshake`
* `http/basic-head`
* `dns/basic-query`

用于通用验证。

---

### 10.2 假设验证模板

例如：

* `http/reverse-proxy-confirm`
* `http/admin-panel-confirm`
* `tls/cdn-edge-confirm`
* `tcp/ssh-banner-confirm`

用于“我怀疑它是什么”的人工验证。

---

### 10.3 实验模板

例如：

* `raw/syn-ack-diff`
* `raw/ttl-variance`
* `raw/badsum-response-check`

用于低层实验。

---

### 10.4 UAM 工作流模板

例如：

* `uam/http-confirm`
* `uam/https-enrich`
* `uam/unknown-8443-check`

这类模板应支持直接从 UAM 拿资产，再展开人工验证流程。

---

## 11. gping 对 UAM 资产“进一步确认”的能力说明

对于一个已经在 UAM 中的 HTTP / HTTPS 资产，gping 的价值绝不能只是再说一句“它是 HTTP”。

gping 必须能够带来 GS 默认自动化阶段通常不会稳定获取的上下文信息，例如：

* 不同 Host / SNI 下的返回差异
* 指定 Path 的返回行为
* 状态码差异（200 / 301 / 401 / 403）
* Server Header
* Title
* Location
* Content-Length
* 页面关键字
* TLS 证书 Subject / SAN / Issuer
* ALPN
* 特定 Header 特征

这类信息用于：

* 补充 UAM 的资产画像
* 支撑人工确认
* 支撑待定/覆盖决策
* 给后续专项扫描提供依据

---

## 12. 从 UAM 读取资产并执行确认的标准流程

### 12.1 读取资产

从 UAM 中选择目标：

* 某个 Host
* 某个 Endpoint
* 某类 Query 结果

例如选择条件：

* `service=https`
* `verification_state=none`
* `port=443`

---

### 12.2 形成验证意图

操作者需要明确当前目的，例如：

* 补充信息
* 确认服务
* 标为待定
* 覆盖原判断
* 执行某个模板

---

### 12.3 执行动作

gping 根据目标与模板展开动作链，例如：

1. `stack/tls-handshake`
2. `app/http-head /`
3. `app/http-get /health`
4. `app/http-get /admin`

---

### 12.4 提取结果

Interpreter 形成：

* Observation summaries
* service / tls / http claims
* optional verification claims

---

### 12.5 写回 UAM

如果操作者要求写回，则写入：

* observations
* claims
* projection 更新

写回规则：

* 补信息 -> `observed claims`
* 人工确认 -> `manual claim`
* 人工覆盖 -> `override claim`

---

## 13. 方案自验证

以下为本方案的自验证结果。

---

## 13.1 验证一：是否可以借助 gping 完成 UAM 资产的进一步确认

### 结论

**可以，而且这是 gping 的核心价值之一。**

### 场景

UAM 中已有一个 endpoint：

* IP: `198.51.100.10`
* protocol: `tcp`
* port: `443`
* current_service: `https`
* verification_state: `none`

GS 已经知道它“像 HTTPS”，但无法自动稳定判断更多上下文。

### gping 如何进一步确认

可以从 UAM 取这个 endpoint，然后执行一个人工选择的模板，例如：

`uam/https-enrich`

模板展开动作：

1. `stack/tls-handshake`
2. `app/http-head /`
3. `app/http-get /health`
4. `app/http-get /admin`（可选）

### 能获得哪些“更多信息”

gping 可以进一步获得：

* 证书 Subject / SAN
* ALPN
* Server Header
* Title
* Redirect 行为
* 特定 Path 的状态码
* 内容关键字
* Content-Length
* Host / SNI 依赖行为

### 如何进入 UAM

进入 Observation：

* `request_summary`
* `response_summary`

进入 Claims：

* `service.product=envoy`
* `http.server=envoy`
* `http.title=Admin`
* `service.hostname=example.internal`

如果人工确认服务归类，则进一步写入：

* `verification_state=confirmed`
* `override_service_name=envoy`

### 结论

gping 可以把 GS 的“初步发现”推进为“可确认资产”。

---

## 13.2 验证二：gping 是否可以独立运行并承担类似 Nping 的操作

### 结论

**可以，而且必须可以。**

### 场景

用户不依赖 UAM，只想做原始包实验：

* 自定义 flags
* 调整 ttl
* 构造坏 checksum
* 观察目标响应

### gping 如何完成

通过 raw route 执行：

* 指定目标
* 指定 route=raw
* 指定 flags / ttl / checksum / payload / timeout / retries

gping 负责：

1. 选择出口
2. 构造原始包
3. 建立 capture
4. 匹配回包
5. 输出结果

### 输出结果

例如：

* `route_used=raw`
* `raw_method=tcp-custom`
* `raw_status=rst-ack`
* `rtt_ms=...`
* `request_summary=flags=SYN,FIN ttl=3 badsum=true`
* `response_summary=flags=RST,ACK`

### 结论

gping 作为独立工具，可以完整承担：

* Nping 风格参数化探测
* 畸形包实验
* 包级控制实验
* 无 UAM 下的动作执行与结果输出

---

## 13.3 验证三：模板化是否会让 gping 退化成另一种自动化扫描器

### 结论

**不会，只要模板系统坚持 manual-first。**

### 原因

GS 的职责是自动发现与覆盖。
gping 模板的职责是：

* 将常见人工确认流程沉淀为可复用剧本
* 在操作者怀疑某类资产时快速调用
* 保持动作链、参数、提取规则可解释

### 正确的模板语义

模板不是：

* 自动对所有目标批量执行
* 默认代替 GS 扫描

模板应是：

* 由操作者明确选择
* 针对某个验证意图
* 输出更深的证据与上下文
* 最终是否确认、待定、覆盖由人决定

### 结论

模板不会让 gping 失去意义，反而是它作为“人工增强验证工具”的核心能力之一。

---

## 14. 最终结论

gping 的正式落地方向应总结为以下三点：

### 第一

**gping 必须是统一动作生命周期引擎。**
raw / stack / app 只是三个 RouteExecutor，而不是三个孤立程序。

### 第二

**gping 的输出必须天然映射到 `GPingObservationInput`。**
每个最小动作都应独立形成 observation、claims 与 assertion，从而零摩擦接入 UAM。

### 第三

**gping 必须坚持 manual-first。**
它不是再做一遍 GS，而是为操作者提供：

* 独立的 Nping 风格实验能力
* 面向 UAM 资产的定向确认能力
* 模板化的可复用验证剧本
* confirmed / pending / override 的资产确认闭环

---

## 15. 实施建议（MVP）

建议 gping 第一阶段只打通最小闭环：

### 路线 MVP

#### Raw

* `tcp-syn`
* `icmp-echo-raw`

#### Stack

* `tcp-connect`
* `tls-handshake`

#### App

* `http-get`
* `http-head`

### Claims MVP

* `network.reachability`
* `network.port_state`
* `service.name`
* `service.product`
* `service.banner`
* `user.verification_state`
* `user.override_service_name`

### 模板 MVP

* `uam/https-enrich`
* `http/reverse-proxy-confirm`
* `raw/basic-syn-check`

### UAM 闭环 MVP

支持：

* 从 UAM 读取 endpoint
* 执行模板或显式动作
* 形成 observations
* 写入 claims
* 推进 projection

---

## 16. 最终判断

本方案满足以下要求：

* gping 可以进一步确认 UAM 中已有资产，并获取 GS 不适合默认自动化获取的更多上下文。
* gping 可以作为独立工具运行，完成类似 Nping 的自由探测与实验。
* gping 可以通过模板化沉淀人工验证剧本，同时不退化为另一种自动扫描器。
* gping 的结果可以天然无缝接入当前 UAM 契约与投影机制。

因此，本方案可以作为当前项目文档中 **gping 补充设计** 的正式基础版本。

```
