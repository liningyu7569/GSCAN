# Going_Scan V2 当前进度

## 当前阶段

当前项目已经从“第一阶段末尾”进入“第二阶段前半段”。

第一阶段的核心目标是：

- 高性能原始扫描主链收口
- 多协议 L4 事实流打通
- 可用 L7 服务识别落地
- 最终画像输出稳定

这一部分已经完成。

当前第二阶段已经正式落地的是：

- UAM SQLite 契约层
- GS -> UAM 正式接入
- UAM 基础查询与综合报告

## 已完成

### L3/L4 核心

- 原始发包与 `pcap` 收包链路
- 路由解析与主动 ARP
- 目标迭代与随机化遍历
- 主机探活
- TCP SYN 扫描
- TCP ACK 扫描
- TCP Window 扫描
- UDP 扫描
- 回包张量判定
- 结果流与终端输出

### CLI 与任务调度

- 统一的 CLI 入口
- 多 profile 扫描任务生成
- 默认端口 / `-F` / `--top-ports`
- 不支持参数显式拒绝
- 输出文件配置

### L7 服务识别

- Nmap 探针库内嵌
- 探针解析与端口倒排索引
- `sslports` / `fallback` 支持
- `rarity` / `totalwaitms` 支持
- TCP / UDP 区分调度
- 分段响应累计读取
- 结构化服务指纹输出

### 输出与画像

- 实时事实流输出
- JSON 画像导出
- YAML 画像导出
- `summary_state` 聚合
- `facts` 保留
- 指纹字段透传

### UAM / SQLite

- `Run / Host / Endpoint / Observation / Claim / Projection / ModuleResult` 完整模型
- SQLite schema、索引、视图
- GS Run 元数据写入
- GS 主机探活写入
- GS L4 Observation / Claim 写入
- GS L7 enrichment 写入
- Host / Endpoint 当前 Projection 刷新
- `uam runs`
- `uam hosts`
- `uam endpoints`
- `uam observations`
- `uam report`

### gping / module 契约层

- gping Run / Observation / Claim 接口
- `manual / override / verification_state` 契约准备
- module Run / Observation / Claim / ModuleResult 接口

### 测试

- CLI 参数与 profile 测试
- L4 路径测试
- ICMP / UDP / TCP 张量测试
- 任务生成测试
- L7 调度与识别测试
- 画像聚合与文件输出测试
- GS -> UAM ingest 测试
- gping / module 契约测试
- UAM 查询与综合报告测试

## 当前支持的扫描方式

- `tcp-syn`
- `tcp-ack`
- `tcp-window`
- `udp`

默认端口扫描方式为 `tcp-syn`。

L7 当前只消费：

- `tcp-syn open`
- `udp open`

## 当前支持的输出

### 扫描输出

- 终端实时结果
- `json`
- `yaml`

### UAM 输出

- SQLite 资产状态库
- JSON 查询结果
- 文本综合报告

## 当前明确已接入

- UAM 正式持久化
- GS 全链路主要事实进入 UAM
- UAM 查询入口
- UAM 综合报告

## 当前明确未接入

- `connect`
- `osscan`
- `protocol`
- `idle scan`
- `spoof-ip`
- `source-port`
- `fragment`
- `badsum`
- `data-length`
- `decoys`
- `defeat-rst-ratelimit`
- gping 执行器本体
- 深层 HTTP / FTP / DB 扫描引擎
- 专项扫描生产者

## 当前边界

当前阶段已经可以稳定承担：

1. 高速发现
2. 服务识别
3. 结构化画像
4. 资产状态沉淀
5. 面向用户的 UAM 查询

但还不是完整的纵深验证平台。

当前还需要继续推进的部分：

1. 更强的 UAM 查询与筛选体验
2. gping 执行器本体
3. 专项扫描生产者
4. 更完整的人工确认工作流
5. 更强的持久化吞吐优化

## 下一阶段建议方向

推荐下一阶段按下面顺序推进：

1. 继续增强 UAM 查询与资产查看体验
2. 落地 gping 的最小可用执行器
3. 让 gping 真正写入 `manual / override / pending`
4. 选择一个专项方向先接入 `module_results`

这样可以让“高速发现 -> 状态沉淀 -> 定向确认 -> 专项深扫”开始真正闭环。
