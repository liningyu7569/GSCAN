# Going_Scan

> 高性能网络资产扫描与分析平台 —— 发现、沉淀、验证、扩展

<p align="center">
  <a href="README_CN.md"><img src="https://img.shields.io/badge/lang-中文-green.svg" alt="中文"></a>
  <a href="README.md"><img src="https://img.shields.io/badge/lang-English-blue.svg" alt="English"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
</p>

---

## 项目定义

Going_Scan 是一个 **Go 语言编写的高性能网络资产扫描与分析平台**，由三个子系统协同构成完整的资产侦察工作流：

| 工具 | 角色 | 核心使命 |
|------|------|----------|
| **GS** | 高速发现引擎 | 大规模、高吞吐的自动资产发现 |
| **UAM** | 统一资产模型 | 资产身份、观察、断言、视图的长期存储 |
| **gping** | 定向验证探针 | 人工驱动的精准确认、修订、覆盖 |

GS 负责"广撒网"，gping 负责"精确认"，UAM 负责"长期记"。三者共享同一个 SQLite 数据库作为数据交换中心。

---

## 设计理念

传统扫描器通常在两个方向上做取舍：要么偏重吞吐、把结果压缩成"端口是否开放"；要么偏重识别、把大量时间消耗在逐连接探测上。

Going_Scan 把这两件事拆开并串联：

- **L4 层**：高速、无状态、可控的原始探测，只管快速发现
- **L7 层**：只消费可信结果，做服务识别与指纹提取
- **输出层**：统一聚合事实流，生成结构化画像
- **资产层 (UAM)**：沉淀所有发现为可追溯的资产知识
- **验证层 (gping)**：对可疑端点做定向确认，回写资产状态

最终目标不是"做一个更强的扫描器"，而是**形成一个可追溯、可确认、可扩展的资产系统**。

---

## 核心能力

### L4 扫描模式

- **TCP SYN** — 半开扫描（默认），最常用的端口扫描方式
- **TCP ACK** — 防火墙规则探测，判断端口是否被过滤
- **TCP Window** — 利用 TCP Window 字段辅助判定端口状态
- **UDP** — UDP 端口状态探测
- **主机探活** — ICMP Echo / TCP / UDP 多协议探活联动，结果实时推进端口扫描

### L7 服务识别

- 内嵌 nmap-service-probes 探针数据库
- 正则预编译 + 端口索引加速匹配
- 提取字段：service, product, version, info, hostname, os, device, cpes
- 支持 TCP/UDP、SSL 端口、fallback 探针、rarity 分级

### gping 应用层适配器

HTTP(S)、DNS、SSH（含 ECDH 密钥交换 + SHA256 主机密钥指纹）、MySQL（含 MariaDB/Percona flavor 检测）、Redis（RESP 协议 + INFO 解析）、FTP（RFC 959 多行回复）、SMTP（含 STARTTLS 证书提取）

### gping 三路线架构

| 路线 | 定位 | 典型方法 |
|------|------|----------|
| **Raw** | 绕过 OS 协议栈的包级控制 | tcp-syn, icmp-echo-raw |
| **Stack** | 使用 OS 协议栈的真实通信 | tcp-connect, tls-handshake, banner-read |
| **App** | 应用层协议适配器 | HTTP/DNS/SSH/MySQL/Redis/FTP/SMTP |

---

## 核心技术特色

**PacketTensor 极限压缩分类** — 收到的回包被压缩为 32 位轻量状态张量（uint32），用 O(1) 位运算完成 TCP/UDP/ICMP 端口状态判定，全程零 GC 压力。位布局：bits 0-7 TCP Flags/ICMP Type，bits 8-15 IP TTL，bits 16-19 Window Size/ICMP Code，bits 20-27 IP Protocol，0xFFFFFFFF 为超时魔术字。

**CWND 自适应并发控制** — 模仿 TCP 拥塞控制算法：成功收到回包时增加并发窗口，超时时乘性减半。引擎的并发度随网络状况自动调节，配合 SRTT 指数平滑和 RTO 动态计算，形成完整的自适应控制闭环。

**Channel ID 物理匹配** — 将通道 ID 编码到发包源端口号中，收包时直接从回包的目的端口 O(1) 定位到对应探针，无需查表或遍历。配合 64 位校验码原子比对，确保回包精确匹配到发起探针。

**零分配发包流水线** — 通过 sync.Pool 复用 128 字节发包缓冲区，直接在池化内存上构建 L2/L3/L4 报文，配合 Lock-Free Ring Buffer（65536 容量）完成高吞吐结果流的无锁传递。

**五层 UAM 资产模型** — Identity（身份）→ Observation（观察）→ Claim（断言）→ Projection（投影）→ Extension（扩展），每层职责不可混淆。Claim 优先级体系：override(4) > manual(3) > observed(2) > inferred(1)，确保人工确认不被自动扫描覆盖。

**gping 模板化验证** — 16 个内置 YAML 模板，支持 `${var}` 变量展开、条件执行（when DSL）、多动作编排、提取规则（extracts）和推荐规则（recommend），将常见验证流程标准化。

---

## 实测数据：C 类网段扫描

以下数据来自 2026 年 4 月 21 日对 `123.X.225.0/24`（256 个 IP，Top 50 端口，SYN + 服务识别，T4 计时模板）的真实扫描。

### 扫描性能总览

![Scan Dashboard](doc/images/dashboard.png)

### 性能时间线

![Performance Timeline](doc/images/perf_timeline.png)

扫描在 38.4 秒内完成，CWND 和 RTO 随网络状况自适应调节：

![CWND & RTO Dynamics](doc/images/cwnd_rto.png)

### 服务分布

335 个开放端口上的服务类型分布：

![Service Distribution](doc/images/service_distribution.png)

### Web 服务器识别

从 HTTP + HTTPS 端点中识别到的 Web 服务器类型：

![Web Servers](doc/images/web_servers.png)

### 吞吐量统计

![Throughput](doc/images/throughput.png)

### gping 定向验证

四个目标端点的验证步骤耗时（HTTPS 四步全链路、SSH 三步确认、MySQL 两步 + SSL 跳过、HTTP Banner 超时 + 应用层验证）：

![gping Results](doc/images/gping_results.png)

---

## 快速开始

### 环境要求

- Go 1.24+
- libpcap / npcap 开发库
- Linux 或 macOS（需要 root 权限运行扫描）
- gcc（CGO 编译 SQLite 需要）

### 编译

```bash
go build -o goscan .
./goscan --help
```

### 运行测试

```bash
go test ./...
```

---

## 典型工作流

### 基础场景：快速扫描

```bash
# C 类网段快速 SYN 扫描 + 服务识别，输出 JSON 画像
./goscan scan 192.168.1.0/24 --syn -F -V -o report.json
```

### 完整场景：GS + UAM + gping 资产闭环

**第一步**：GS 发现资产并沉淀到 UAM

```bash
./goscan scan 192.168.1.0/24 --syn -V --uam-db uam.db
```

**第二步**：查看发现的可疑 HTTPS 端点

```bash
./goscan gping candidates --uam-db uam.db --uam-service https
```

**第三步**：定向验证并确认

```bash
./goscan gping --uam-db uam.db --uam-service https --pick-index 1 \
  --template uam/https-enrich --assert confirmed
```

**第四步**：查看主机的完整资产报告

```bash
./goscan uam report --db uam.db --ip 192.168.1.10
```

---

## 常用命令

### L4 扫描模式

```bash
# 默认 SYN 扫描
./goscan scan 192.168.1.10 -p 22,80,443

# 多方法组合
./goscan scan 192.168.1.10 --syn --ack --window

# TCP + UDP 混合
./goscan scan 192.168.1.10 --syn --udp -p 53,80,443

# 快速扫描（Top 100 端口）
./goscan scan 192.168.1.0/24 -F

# Top N 端口
./goscan scan 192.168.1.0/24 --top-ports 50
```

### L7 服务识别

```bash
# SYN + 服务识别
./goscan scan 192.168.1.10 --syn -V -p 22,80,443

# 指定端口范围 + 服务识别
./goscan scan 192.168.1.0/24 -p 1-1024 --syn -V -T 4
```

### 输出格式

```bash
# JSON 画像
./goscan scan 192.168.1.10 --syn -V -o report.json

# YAML 画像
./goscan scan 192.168.1.10 --syn -V -o report.yaml

# 显式指定格式
./goscan scan 192.168.1.10 --syn -V -o report.out --output-format yaml
```

### UAM 资产查询

```bash
# 查看运行记录
./goscan uam runs --db uam.db

# 查看主机列表
./goscan uam hosts --db uam.db

# 按 IP 查询端点
./goscan uam endpoints --db uam.db --ip 192.168.1.10

# 按 IP + 端口查询观察历史
./goscan uam observations --db uam.db --ip 192.168.1.10 --port 443

# 综合报告
./goscan uam report --db uam.db --ip 192.168.1.10
```

### gping 定向验证

```bash
# 查看模板
./goscan gping templates
./goscan gping templates --show uam/https-enrich

# 候选目标
./goscan gping candidates --uam-db uam.db --uam-service https

# 预览（不实际执行）
./goscan gping preview --uam-db uam.db --uam-service https --pick-first --template uam/https-enrich

# 执行验证
./goscan gping --uam-db uam.db --uam-service https --pick-first --template uam/https-enrich --assert confirmed

# 独立运行（不依赖 UAM）
./goscan gping --ip 192.168.1.10 --port 443 --method tcp-connect --route stack

# 查看历史
./goscan gping history --uam-db uam.db --ip 192.168.1.10 --port 443 --protocol tcp --verbose
```

### 性能调优

```bash
# 计时模板（T1 最保守，T5 最激进）
./goscan scan 192.168.1.0/24 -p 1-1000 --syn -T 5

# 发包速率限制
./goscan scan 192.168.1.0/24 -p 1-1000 --syn --max-rate 100

# 并发度控制
./goscan scan 192.168.1.0/24 -p 1-1000 --syn --min-parallelism 16 --max-parallelism 64

# 重试与超时
./goscan scan 192.168.1.0/24 -p 1-1000 --syn --max-retries 1 --max-rtt-timeout 500
```

---

## 项目结构

```
cmd/                CLI 入口（root、scan、gping、uam 子命令）
pkg/core/           L4 引擎、任务调度、结果流、画像输出
pkg/l7/             L7 服务识别引擎与 nmap 探针解析
pkg/routing/        路由与网关解析
pkg/target/         目标迭代器与 CIDR 遍历
pkg/queue/          结果队列与 Lock-Free Ring Buffer
internal/gping/     gping 执行器、模板、预览与历史回看
internal/uam/       UAM 契约层、SQLite 存储、查询与报告
doc/                项目文档
scripts/            辅助脚本（图表生成等）
```

### 推荐阅读顺序

1. `main.go` — 程序入口
2. `cmd/root.go` — CLI 命令树
3. `pkg/core/engine.go` — L4 引擎主循环
4. `pkg/core/tensor.go` — PacketTensor 分类器
5. `pkg/core/l7engine.go` — L7 服务识别引擎
6. `pkg/core/report.go` — 画像输出
7. `pkg/l7/nmap_parser.go` — nmap 探针解析
8. `internal/gping/runner.go` — gping 生命周期
9. `internal/gping/resolver.go` — 目标解析
10. `internal/uam/service/ingest_gs.go` — GS → UAM 写入
11. `internal/uam/service/query.go` — UAM 查询服务
12. `internal/uam/service/report.go` — 综合报告

---

## 文档

- [项目综述](doc/project-overview.md) — 项目定义、技术特色、三工具协作
- [完整技术文档](doc/project-reference.md) — 架构细节、数据流、CLI 参考、设计决策

---

## 免责声明

本工具**仅限授权的安全研究和教育目的**使用。使用者在扫描任何非自有网络或系统前，必须获得明确授权。作者对因滥用本工具造成的任何损失不承担法律责任。未经授权的端口扫描可能违反相关法律法规。

---

## 开源贡献

本项目当前为个人维护，欢迎 Bug 反馈、功能建议和 Pull Request。有任何问题或合作意向，请联系 **liningyu7569@gmail.com**。

---

## 技术栈

- **语言**：Go 1.24+
- **包依赖**：libpcap / npcap
- **存储**：SQLite（WAL 模式 + 外键约束）
- **权限**：Linux/macOS 需 root 或等效权限运行扫描
