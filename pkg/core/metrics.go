package core

import (
	"Going_Scan/pkg/conf"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// ScanMetrics 记录全局扫描性能指标，所有字段必须通过 atomic 操作
type ScanMetrics struct {
	TotalTasks     int64 // 计划扫描的总任务数
	TasksDone      int64 // 已完成的任务数 (成功+超时)
	PacketsSent    int64 // 实际发出的物理包数量 (含重传)
	PacketsMatched int64 // 成功匹配到正在飞行探针的回包数
	DispatchDrops  int64 // 因通道已满而被丢弃的匹配回包
	OpenPorts      int64 // 发现的开放端口数量
	Filtered       int64 // 超时/被过滤的数量

	StartTime time.Time
}

const (
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

var GlobalMetrics = &ScanMetrics{}

// InitMetrics 扫描开始前初始化时间
func InitMetrics(totalTasks int64) {
	GlobalMetrics = &ScanMetrics{
		TotalTasks: totalTasks,
		StartTime:  time.Now(),
	}
}

// StartMonitor 启动一个后台实时监控面板 (类似 Nmap 的按下空格后的输出)
func StartMonitor(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second) // 每 2 秒刷新一次监控
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 扫描结束时打印最终汇总
			//printSummary()
			return
		case <-ticker.C:
			// 实时打印进度
			printProgress()
		}
	}
}

func printProgress() {
	done := atomic.LoadInt64(&GlobalMetrics.TasksDone)
	total := atomic.LoadInt64(&GlobalMetrics.TotalTasks)
	sent := atomic.LoadInt64(&GlobalMetrics.PacketsSent)
	matched := atomic.LoadInt64(&GlobalMetrics.PacketsMatched)
	open := atomic.LoadInt64(&GlobalMetrics.OpenPorts)

	elapsed := time.Since(GlobalMetrics.StartTime).Seconds()
	if elapsed == 0 {
		elapsed = 1
	}

	pps := float64(sent) / elapsed // 实时发包率 (Packets Per Second)
	percent := 100.0
	if total > 0 {
		percent = float64(done) / float64(total) * 100
	}

	fmt.Printf("[Stats] %.2fs elapsed | %.2f%% done | %d Open | %d Sent | %d Matched | %.0f pps\n",
		elapsed, percent, open, sent, matched, pps)
}

func printSummary() {
	elapsed := time.Since(GlobalMetrics.StartTime)
	open := atomic.LoadInt64(&GlobalMetrics.OpenPorts)
	sent := atomic.LoadInt64(&GlobalMetrics.PacketsSent)
	matched := atomic.LoadInt64(&GlobalMetrics.PacketsMatched)
	dispatchDrops := atomic.LoadInt64(&GlobalMetrics.DispatchDrops)
	seconds := elapsed.Seconds()
	if seconds == 0 {
		seconds = 1
	}

	fmt.Printf("\n================ Going_Scan Report ================\n")
	fmt.Printf("Scan completed in %v\n", elapsed)
	fmt.Printf("Total Packets Sent: %d\n", sent)
	fmt.Printf("Matched Replies: %d\n", matched)
	fmt.Printf("Dispatcher Drops: %d\n", dispatchDrops)
	fmt.Printf("Open Ports Found: %d\n", open)
	fmt.Printf("Average Speed: %.0f pps\n", float64(sent)/seconds)
	fmt.Printf("===================================================\n")
}

// PersistDone 关键同步锁：主进程 (main) 需阻塞监听此通道，确认所有日志打印完毕后方可退出
var PersistDone = make(chan struct{})

// protocolToStr 边缘格式化：将内核协议号翻译为人类可读字符串
func protocolToStr(p uint8) string {
	switch p {
	case syscall.IPPROTO_TCP:
		return "TCP"
	case syscall.IPPROTO_UDP:
		return "UDP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", p)
	}
}

// RunResultPersister 持久化大管家：专职负责战果的终端回显与多路落盘
func RunResultPersister() {
	var file *os.File
	var err error
	var encoder *json.Encoder

	// 1. JSONL 文件落盘初始化 (直接读取全局配置)
	if conf.GlobalOps.IsOutputFile && conf.GlobalOps.OutputFile != "" {
		file, err = os.OpenFile(conf.GlobalOps.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("[!] 无法创建 JSONL 输出文件: %v\n", err)
		} else {
			defer file.Close()
			encoder = json.NewEncoder(file)
			fmt.Printf("[+] 战果将实时持久化至: %s\n", conf.GlobalOps.OutputFile)
		}
	}

	// 2. SQLite 落盘钩子初始化 (预留)
	initSQLiteHook()

	fmt.Println("\n====== [Scan Results] ======")

	// 3. 消费全局唯一的 ResultStream
	for result := range ResultStream {
		protoStr := protocolToStr(result.Protocol)

		// ----------------------------------------------------
		// 终端可视化回显 (区分 -V 模式与普通模式)
		// ----------------------------------------------------
		if result.Service == "" {
			// 极速端口透传模式
			fmt.Printf("[+] %-15s %5d/%-3s %sopen%s\n",
				result.IPStr, result.Port, protoStr, ColorGreen, ColorReset)
		} else if result.Service != "unreachable" {
			// 服务指纹模式 (-V)
			// 如果是 unknown，标黄；否则标青色
			serviceColor := ColorCyan
			if result.Service == "unknown" {
				serviceColor = ColorYellow
			}

			bannerStr := result.Banner
			// 如果返回的结果太长，强制截断，保卫表格队列
			if len(bannerStr) > 50 {
				bannerStr = bannerStr[:47] + "..."
			}

			fmt.Printf("[+] %-15s %5d/%-3s %sopen%s  %-12s %s\n",
				result.IPStr,
				result.Port,
				protoStr,
				ColorGreen, ColorReset,
				serviceColor+result.Service+ColorReset,
				ColorBlue+bannerStr+ColorReset)
		}

		// ----------------------------------------------------
		// 磁盘持久化一：JSON Lines
		// ----------------------------------------------------
		if encoder != nil {
			// 重组结构体，隐藏 uint8 协议号，输出直观的字符串，并利用 omitempty 保持文件整洁
			outputData := struct {
				IP       string `json:"ip"`
				Port     uint16 `json:"port"`
				Protocol string `json:"protocol"`
				State    string `json:"state"`
				Service  string `json:"service,omitempty"`
				Banner   string `json:"banner,omitempty"`
			}{
				IP:       result.IPStr,
				Port:     result.Port,
				Protocol: protoStr,
				State:    result.State,
				Service:  result.Service,
				Banner:   result.Banner,
			}
			_ = encoder.Encode(outputData)
		}

		// ----------------------------------------------------
		// 磁盘持久化二：SQLite (钩子调用)
		// ----------------------------------------------------
		saveToSQLiteHook(result, protoStr)
	}

	fmt.Println("============================")
	fmt.Println("[Persister] 终端回显完毕，所有持久化落盘队列已清空，安全退出。")

	// 敲响最后一记下班铃声！允许 main 函数彻底退出。
	close(PersistDone)
}

// =========================================================================
// SQLite 持久化钩子 (Hooks for Tier-2 Deep Scan)
// 在下一阶段的漏洞扫描中，关系型数据库能更方便地进行资产聚合、状态追踪和去重
// =========================================================================

func initSQLiteHook() {
	// TODO (Phase 2):
	// 1. 读取 conf.GlobalOps.EnableSQLite 等配置
	// 2. 初始化 db.Conn 池
	// 3. 执行 CREATE TABLE IF NOT EXISTS assets (...)
}

func saveToSQLiteHook(result ScanResult, protoStr string) {
	// TODO (Phase 2):
	// 执行 INSERT OR REPLACE INTO assets (ip, port, protocol, service, banner) VALUES (...)
}
