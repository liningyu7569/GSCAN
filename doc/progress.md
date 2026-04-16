# Going_Scan V2 当前进度

## 当前阶段

当前项目已经进入“第二阶段总体收口”。

此时仓库里的主线已经稳定成三层：

1. GS：高速发现与服务识别
2. UAM：统一资产状态层
3. gping：围绕现有资产做定向确认、人工增强和轻量 enrich

如果只看主骨架目标，`GS + UAM + gping 第二阶段主链` 已经基本成型。

---

## 已完成

### GS 主链

- 原始发包与 `pcap` 收包
- 主机探活
- TCP SYN / ACK / Window
- UDP 扫描
- 多 profile 任务生成
- 实时事实流输出
- JSON / YAML 画像导出
- L7 服务识别与结构化指纹提取

### UAM / SQLite

- `Run / Host / Endpoint / Observation / Claim / Projection / ModuleResult`
- SQLite schema、索引、视图
- GS Run 元数据写入
- GS L4 / L7 Observation 与 Claim 写入
- Host / Endpoint 当前 Projection 刷新
- `uam runs / hosts / endpoints / observations / report`

### gping 第二阶段主线

- `goscan gping` 命令入口
- 字面目标、URL、`--uam-endpoint`、UAM 条件筛选选目标
- `gping templates`
- `gping candidates`
- `gping preview`
- `gping history`
- 结果写回 UAM
- `manual / override / verification_state` 契约落地
- `extra_json` 证据落库与历史回看
- `DSL v1` 兼容骨架
- `app adapter v1`
- `extract / recommend` 接缝

### gping 当前支持的方法

- `raw`
  - `tcp-syn`
  - `tcp-raw`
  - `icmp-echo-raw`
  - `icmp-raw`
- `stack`
  - `tcp-connect`
  - `banner-read`
  - `tls-handshake`
- `app`
  - HTTP: `http-head / http-get / http-post`
  - DNS: `dns-query`
  - FTP: `ftp-banner / ftp-feat / ftp-auth-tls`
  - SMTP: `smtp-banner / smtp-ehlo / smtp-starttls`
  - Redis: `redis-ping / redis-info-server / redis-info-replication`
  - SSH: `ssh-banner / ssh-kexinit / ssh-hostkey`
  - MySQL: `mysql-greeting / mysql-capabilities / mysql-starttls`

### gping 当前模板体系

- 内置模板加载
- 外部 YAML 模板加载
- `workflow` 与旧 `actions` 兼容
- `vars`
- `params`
- `when`
- `continue_on_error`
- `extract`
- `recommend`
- `suggest`

### gping 当前 raw 自由注入能力

- `TTL / TOS / IP ID / DF`
- `source port`
- `TCP flags / seq / ack / window`
- `ICMP type / code / id / seq`
- 文本 payload 与十六进制 payload
- 故意坏校验和
- raw 动作级重试

### 测试

- GS 核心路径测试
- L7 服务识别测试
- UAM ingest / query / report 测试
- gping 目标解析测试
- gping 模板规划测试
- gping raw / stack / app 执行测试
- gping adapter 协议桩测试
- gping UAM 写回测试
- gping history / preview / candidate 测试

---

## 当前支持的用户入口

### GS

- `goscan scan ...`

### UAM

- `goscan uam runs`
- `goscan uam hosts`
- `goscan uam endpoints`
- `goscan uam observations`
- `goscan uam report`

### gping

- `goscan gping`
- `goscan gping templates`
- `goscan gping candidates`
- `goscan gping preview`
- `goscan gping history`

---

## 当前仍然刻意未做

- 重型协议适配器
- 深交互式协议解析器
- FTP 数据通道与目录行为
- SSH 会话与命令执行
- MySQL / Redis / SMTP 认证后深交互
- UDP raw 路线
- 多包序列化 raw 实验
- 更复杂的 UAM 查询 DSL

---

## 当前边界

当前 `gping` 更合适的理解是：

- 一个已经可用的定向确认器
- 一个已经能回写 UAM 的人工增强工具
- 一个已经具备轻量协议 adapter 和常见 raw 注入能力的多路线探测器

但它还不是：

- 通用深度协议扫描框架
- 所有协议都已模板化的万能确认系统
- 专项扫描器的替代品

更合适的边界仍然是：

- 轻量、确认级、低副作用动作继续进入 `gping`
- 复杂、重交互、强业务语义能力进入后续专项解析器或 module

---

## 当前阶段结论

截至 2026-04-15，Going_Scan 当前已经可以稳定承担：

1. 高速发现
2. 服务识别
3. 结构化画像
4. 统一资产状态沉淀
5. 面向资产的定向确认
6. 面向单目标的常见 raw 参数化实验

因此这一阶段的重点已经从“把骨架搭出来”转成：

> 在保持边界清晰的前提下，围绕现有 GS / UAM / gping 主链做语义打磨、协议一致性收口与实验能力增强。
