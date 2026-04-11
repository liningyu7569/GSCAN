# Going_Scan

Going_Scan 是一个以原始发包和 `pcap` 收包为核心的高性能网络扫描器。它将 L4 无状态探测与 L7 服务识别组合在同一条结果流水线中，既强调吞吐能力，也强调结果的结构化表达。

项目当前已经具备完整的主机探活、TCP/UDP 多协议端口扫描、服务识别、最终画像导出能力，适合继续向更深层的协议扫描与资产分析演进。

## Features

- 基于原始报文构造的无状态 L4 扫描
- `pcap` 驱动的高速收包与回包匹配
- `PacketTensor` 风格的 O(1) 状态判定
- TCP SYN / ACK / Window 与 UDP 多协议扫描
- 流式主机探活与端口扫描联动
- L7 服务识别与结构化指纹提取
- 基于 `nmap-service-probes` 的综合服务探测
- JSON / YAML 最终画像导出

## Why Going_Scan

传统扫描器通常在两个方向上做取舍：

- 要么偏重吞吐，把结果压缩成“端口是否开放”
- 要么偏重识别，把大量时间消耗在连接和协议探测上

Going_Scan 的设计目标是把这两件事拆开并串联起来：

- L4 层负责高速、无状态、可控的原始探测
- L7 层只消费可信结果，负责识别服务与提取指纹
- 输出层统一聚合事实流，生成最终画像

这使它既适合做高速发现，也适合作为后续深层扫描系统的前置引擎。

## Architecture Overview

### L4: Stateless Packet Tensor Engine

L4 部分是 Going_Scan 的性能核心。

它不依赖传统 `connect()` 作为主扫描路径，而是直接构造以太网、IP、TCP/UDP/ICMP 报文，通过网卡发出，再通过 `pcap` 收包完成匹配与判定。

这一层的关键点有三个：

#### 1. Raw packet injection

- 直接构造 L2/L3/L4 报文
- 发包与收包完全解耦
- 不让操作系统 Socket 状态机主导扫描节奏

#### 2. PacketTensor-style classification

收到的回包不会进入一套沉重的逐层解释逻辑，而是被快速压缩为一个轻量状态张量，再用位运算和固定规则完成判定。

这让以下场景可以稳定输出：

- TCP SYN: `open / closed / filtered`
- TCP ACK: `unfiltered / filtered`
- TCP Window: `open / closed / filtered`
- UDP: `open / closed / filtered`
- ICMP: 主机探活反馈

#### 3. High-throughput stateless pipeline

L4 引擎采用了适合高并发扫描的流水线式设计：

- 发包协程与回包分发分离
- 使用锁无关结果缓冲区承接战果
- 通过 channel ID + 目标校验码完成 O(1) 物理匹配
- 主机探活结果可直接推进端口扫描，不必等待全量探活结束

结果是：L4 层更接近一个“无状态探测引擎”，而不是一个逐连接处理器。

### L7: Integrated Service Scan Engine

L7 部分负责把“端口开放”进一步转换为“这是什么服务”。

它不是对所有结果无差别进行连接探测，而是只对可信开放结果做服务识别，这样既能减少无效连接，也能保持整个扫描过程的可靠性。

L7 的核心能力包括：

- 内嵌 `nmap-service-probes`
- 启动期完成探针解析与正则预编译
- 基于端口索引选择候选探针
- 支持 `ports` / `sslports` / `fallback`
- 支持 `rarity` / `totalwaitms`
- 区分 TCP / UDP 探针路径
- 支持分段响应累计读取
- 提取结构化服务指纹

最终输出不仅有 `service` 和 `banner`，还会尽可能带出：

- `product`
- `version`
- `info`
- `hostname`
- `os`
- `device`
- `cpes`

这使 Going_Scan 的 L7 阶段不仅是“看端口像不像 HTTP”，而是一个综合服务识别引擎。

## Scan Model

Going_Scan 当前采用“事实流 + 最终画像”的结果模型。

扫描过程中，每一个结果都会以独立事实的形式输出，例如：

- `tcp-syn=open`
- `tcp-ack=unfiltered`
- `tcp-window=open`
- `udp=open`

扫描结束后，系统会将这些事实聚合为端口画像，并给出：

- `summary_state`
- `facts`
- `service`
- `product`
- `version`
- `banner`

这种设计保留了原始判断依据，也为后续深层扫描留出了干净的数据接口。

## Project Layout

```text
cmd/                CLI 入口
pkg/core/           L4 引擎、任务调度、结果流、画像输出
pkg/l7/             L7 服务识别引擎与 Nmap 探针解析
pkg/routing/        路由与网关解析
pkg/target/         目标迭代器与 CIDR 遍历
pkg/queue/          结果队列与无锁缓冲
doc/                项目日志与阶段进展
```

## Requirements

- Go 1.24 或兼容版本
- 可用的 `libpcap` / `npcap`
- 具备原始发包与抓包权限

在 Linux 和 macOS 上，通常需要 `root` 或等效权限运行扫描命令。

## Build

```bash
go build -o goscan .
```

## Test

```bash
go test ./...
```

## Quick Start

默认扫描内置高频端口：

```bash
./goscan scan 192.168.1.10
```

扫描指定端口：

```bash
./goscan scan 192.168.1.10 -p 22,80,443
```

扫描一个网段：

```bash
./goscan scan 192.168.1.0/24 -F
```

## Usage

### L4 Scan Modes

默认端口扫描模式是 `tcp-syn`。也可以组合多种 L4 扫描方法：

```bash
./goscan scan 192.168.1.10 --syn --ack --window
```

同时扫描 TCP 与 UDP：

```bash
./goscan scan 192.168.1.10 --syn --udp -p 53,80,443
```

只做 UDP 扫描：

```bash
./goscan scan 192.168.1.10 --udp -p 53,123,161
```

使用内置高频端口集：

```bash
./goscan scan 192.168.1.10 -F
```

使用前 N 个内置高频端口：

```bash
./goscan scan 192.168.1.10 --top-ports 50
```

### L7 Service Detection

开启 `-V` 后，Going_Scan 会在 L4 结果基础上执行服务识别：

```bash
./goscan scan 192.168.1.10 --syn -V -p 22,80,443
```

多协议扫描配合 L7：

```bash
./goscan scan 192.168.1.10 --syn --udp -V -p 53,80,443
```

### Output Portraits

导出 JSON 画像：

```bash
./goscan scan 192.168.1.10 --syn --ack --window -V -o report.json
```

导出 YAML 画像：

```bash
./goscan scan 192.168.1.10 --syn --udp -V -o report.yaml
```

显式指定格式：

```bash
./goscan scan 192.168.1.10 --syn -V -o report.out --output-format yaml
```

## Output Format

终端输出是实时事实流，文件输出是扫描结束后的最终画像。

最终画像包含：

- 扫描命令与目标元数据
- 扫描 profile 列表
- 解析后的端口列表
- 主机与端口画像
- 原始 `facts`
- 聚合后的 `summary_state`
- L7 结构化指纹

这意味着 Going_Scan 的输出不仅适合人工阅读，也适合后续工具继续消费。

## Example Workflow

1. 使用 L4 模式高速发现开放端口
2. 对可信开放结果执行 L7 服务识别
3. 生成结构化资产画像
4. 将画像作为后续协议专项扫描的输入

这也是 Going_Scan 的核心价值所在：它不仅做扫描，还为后续更深层的自动化分析提供稳定、统一的入口。

## Reading Guide

如果你希望快速理解代码，建议按下面顺序阅读：

- `main.go`
- `cmd/root.go`
- `pkg/core/engine.go`
- `pkg/core/l7engine.go`
- `pkg/core/report.go`
- `pkg/l7/nmap_parser.go`
- `pkg/l7/l7worker.go`

## Documentation

- `doc/dev_log.md`
- `doc/progress.md`
