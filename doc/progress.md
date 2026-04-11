# Going_Scan V2 当前进度

## 当前阶段

当前项目处于第一阶段末尾。

这一阶段的目标是把高性能原始扫描核心、基础多协议能力、可用 L7 服务识别与最终画像输出完整打通。按当前代码状态来看，这个目标已经基本完成。

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

### 测试

- CLI 参数与 profile 测试
- L4 路径测试
- ICMP / UDP / TCP 张量测试
- 任务生成测试
- L7 调度与识别测试
- 画像聚合与文件输出测试

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

- 终端实时结果
- `json`
- `yaml`

输出文件内容是最终画像，不是简单的逐行结果转储。

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
- SQLite 正式持久化
- 深层 HTTP / FTP / DB 扫描引擎

## 当前边界

当前阶段已经可以稳定承担“高速发现 + 服务识别 + 结构化画像”的职责，但还不是完整的纵深扫描平台。

还需要继续推进的部分：

1. 基于当前画像结果的深层扫描分发模型
2. SQLite 数据模型与资产关系固化
3. 更强的拥塞控制与复杂链路层场景加固
4. 更完整的 L7 识别策略与后续协议专项扫描

## 下一阶段建议方向

推荐下一阶段按下面顺序推进：

1. 设计统一的资产与服务结果模型
2. 设计 SQLite 存储结构
3. 设计 `service/cpe -> deeper scanner` 分发逻辑
4. 先落地 HTTP 深扫，再扩展到 FTP、数据库等协议

这样可以让后续不同扫描引擎之间共享一套资产画像与结果关联模型，而不是各自独立生长。
