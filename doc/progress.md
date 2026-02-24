# 项目进度文档（Progress Report）


## 1. 项目概述

本项目目标是使用 Go 语言实现一个高性能、安全合规的网络扫描工具，参考 Nmap 的核心功能与设计理念。第一阶段重点实现主机发现与基本端口扫描（TCP SYN/Connect），后续逐步扩展版本检测、OS 指纹识别等高级特性。

项目采用现代 Go 工程实践：模块化设计、并发优化、清晰的文档记录，力求代码可读性与性能兼顾。

## 2. 当前进度（起步阶段）

### 已完成
- **项目结构初始化**  
  完成标准 Go 项目目录布局：
  cmd/          # CLI 入口
  internal/     # 私有实现包
  pkg/          # 可复用包（暂空）
  docs/         # 文档目录（含本进度文档与技术难点记录）
  go.mod / go.sum
  README.md skeleton
  text- **第一阶段任务规划**  
  明确最小可用系统（MVP）范围：
- 支持 CIDR 与单个 IP 输入
- 主机发现（ICMP Echo Request）
- 基本 TCP 端口扫描（SYN / Connect）
- 常见端口列表与自定义端口范围
- 基本的速率限制与超时控制

### 进行中
- **CLI 参数解析器实现**  
  使用 `github.com/spf13/cobra` 或 `flag` + 自定义封装，实现全局扫描选项（OPS）解析，包括但不限于：
- `-sS`（TCP SYN 扫描）
- `-sT`（TCP Connect 扫描）
- `-p`（端口范围）
- `-T`（定时模板）
- `--min-rtt-timeout`、`--max-rtt-timeout`、`--max-retries` 等常见选项
- **IP 目标解析模块**
- 完成标准 CIDR 解析（`net.ParseCIDR`）
- 正在实现基于**线性同余生成器（LCG）**的非重复随机遍历迭代器  
  目的：实现业内主流扫描工具（如 Nmap、Masscan）的随机化目标顺序，降低检测概率，同时满足：
    - O(1) 空间复杂度（不预生成完整 IP 列表）
    - 满周期覆盖（不重复、不遗漏）
    - 可复现（相同种子产生相同顺序）
- 已选定合适的 LCG 参数并完成初步验证，后续将封装为通用 `TargetIterator` 接口

### 已确定架构方向（纸上谈兵阶段）
采用**生产者-消费者**并发模型，初步设计如下：

| 组件              | 职责                                      | 实现方式                     | 备注                              |
|-------------------|-------------------------------------------|------------------------------|-----------------------------------|
| **Target Producer** | 生成并随机化目标 IP:Port 对               | 单 goroutine + LCG 迭代器    | 控制扫描顺序与速率                |
| **Packet Builder**  | 多 goroutine 构建原始 TCP/IP 包           | gopacket 或自定义 raw socket | 高并发构建，提升发送吞吐          |
| **Packet Sender**   | 单 IO 发送 goroutine                       | 单 raw socket 写通道          | 避免多 socket 竞争，提升稳定性    |
| **Packet Receiver & Filter** | 单 goroutine 捕获并过滤响应包            | pcap 监听 + BPF 过滤器       | 高效过滤无关包，减少 CPU 开销     |
| **Result Consumer** | 处理响应、状态判断、结果汇总              | 多 goroutine worker pool     | 最终输出开放/关闭/过滤状态        |

该架构参考 Masscan/ZMap 高性能设计，同时兼顾 Go 生态实现难度，预计在常规网络环境下可达到万级 PPS 吞吐。

## 3. 下一阶段计划（Target / USI / HSS）
在完成目标解析与 CLI 基础选项后，立即进入核心扫描逻辑实现：

1. **Target Management**
- 统一目标输入抽象（支持 IP、CIDR、范围、文件输入）
- 目标去重与随机化迭代器集成
2. **Unified Scanner Interface (USI)**
- 定义扫描器接口（`Scanner`），便于后续扩展多种扫描类型
3. **Host & Service Scanner (HSS)**
- 实现主机发现（ICMP + TCP/UDP 辅助）
- 实现 TCP SYN 与 Connect 扫描主流程
- 基本结果输出（文本/JSON）

预计完成时间：2026-01-15 ~ 2026-02-28（视难点复杂度调整）

## 4. 风险与注意事项
- Raw socket 在非 Linux 平台需 root 权限，需记录兼容性方案（fallback 到 Connect 扫描）
- LCG 参数需进一步跨平台验证满周期
- 并发模型需压力测试，避免 goroutine 泄漏或死锁

## 5. 总结与展望
项目已脱离纯规划阶段，进入实质编码阶段。当前重点是打磨目标解析与 CLI 基础，确保后续扫描架构能顺利落地。保持“边做边文档”原则，所有技术难点将在 `docs/modules/` 下按模块记录。

下一步：完成 IP 解析器 → 实现 TargetIterator → 开始 USI 接口设计。

**加油，坚持记录，坚持迭代！**