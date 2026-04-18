package core

import (
	"Going_Scan/pkg/conf"
	"context"
	"fmt"
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
	AliveHosts     int64 // 首次确认存活的主机数量

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
	syncGlobalMetrics()
	done := atomic.LoadInt64(&GlobalMetrics.TasksDone)
	total := atomic.LoadInt64(&GlobalMetrics.TotalTasks)
	sent := atomic.LoadInt64(&GlobalMetrics.PacketsSent)
	matched := atomic.LoadInt64(&GlobalMetrics.PacketsMatched)
	open := atomic.LoadInt64(&GlobalMetrics.OpenPorts)
	alive := atomic.LoadInt64(&GlobalMetrics.AliveHosts)
	filtered := atomic.LoadInt64(&GlobalMetrics.Filtered)

	elapsed := time.Since(GlobalMetrics.StartTime).Seconds()
	if elapsed == 0 {
		elapsed = 1
	}

	pps := float64(sent) / elapsed // 实时发包率 (Packets Per Second)
	percent := 100.0
	if total > 0 {
		percent = float64(done) / float64(total) * 100
	}

	fmt.Printf("[Stats] %.2fs elapsed | %.2f%% done | %d Alive | %d Open | %d Filtered | %d Sent | %d Matched | %.0f pps\n",
		elapsed, percent, alive, open, filtered, sent, matched, pps)
}

func printSummary() {
	syncGlobalMetrics()
	elapsed := time.Since(GlobalMetrics.StartTime)
	open := atomic.LoadInt64(&GlobalMetrics.OpenPorts)
	sent := atomic.LoadInt64(&GlobalMetrics.PacketsSent)
	matched := atomic.LoadInt64(&GlobalMetrics.PacketsMatched)
	dispatchDrops := atomic.LoadInt64(&GlobalMetrics.DispatchDrops)
	alive := atomic.LoadInt64(&GlobalMetrics.AliveHosts)
	filtered := atomic.LoadInt64(&GlobalMetrics.Filtered)
	seconds := elapsed.Seconds()
	if seconds == 0 {
		seconds = 1
	}

	fmt.Printf("\n================ Going_Scan Report ================\n")
	fmt.Printf("Scan completed in %v\n", elapsed)
	fmt.Printf("Total Packets Sent: %d\n", sent)
	fmt.Printf("Matched Replies: %d\n", matched)
	fmt.Printf("Dispatcher Drops: %d\n", dispatchDrops)
	fmt.Printf("Alive Hosts Found: %d\n", alive)
	fmt.Printf("Open Ports Found: %d\n", open)
	fmt.Printf("Filtered Tasks: %d\n", filtered)
	fmt.Printf("Average Speed: %.0f pps\n", float64(sent)/seconds)
	fmt.Printf("===================================================\n")
}

func syncGlobalMetrics() {
	atomic.StoreInt64(&GlobalMetrics.PacketsSent, MetricPacketsSent.Read())
	atomic.StoreInt64(&GlobalMetrics.PacketsMatched, MetricPacketsMatch.Read())
	atomic.StoreInt64(&GlobalMetrics.DispatchDrops, MetricDispatchDrops.Read())
	atomic.StoreInt64(&GlobalMetrics.Filtered, MetricFiltered.Read())
	atomic.StoreInt64(&GlobalMetrics.OpenPorts, MetricOpenPorts.Read())
	atomic.StoreInt64(&GlobalMetrics.TasksDone, MetricTasksDone.Read())
	atomic.StoreInt64(&GlobalMetrics.AliveHosts, MetricAliveHosts.Read())
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
	case syscall.IPPROTO_ICMP:
		return "ICMP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", p)
	}
}

// RunResultPersister 持久化大管家：专职负责战果的终端回显与多路落盘
func RunResultPersister() {
	aggregator := NewPortraitAggregator()

	// 1. 最终画像文件输出初始化
	if conf.GlobalOps.IsOutputFile && conf.GlobalOps.OutputFile != "" {
		fmt.Printf("[+] 扫描完成后将输出聚合画像至: %s\n", conf.GlobalOps.OutputFile)
	}

	// 2. SQLite 落盘钩子初始化 (预留)
	initSQLiteHook()

	fmt.Println("\n====== [Scan Results] ======")

	// 3. 消费全局唯一的 ResultStream
	for result := range ResultStream {
		protoStr := protocolToStr(result.Protocol)
		stateColor := ColorYellow
		if result.State == "open" {
			stateColor = ColorGreen
		}

		// ----------------------------------------------------
		// 终端可视化回显 (区分 -V 模式与普通模式)
		// ----------------------------------------------------
		if result.Service == "" {
			fmt.Printf("[+] %-15s %5d/%-3s %-10s %s%s%s\n",
				result.IPStr, result.Port, protoStr, result.Method, stateColor, result.State, ColorReset)
		} else if result.Service != "unreachable" {
			serviceColor := ColorCyan
			if result.Service == "unknown" {
				serviceColor = ColorYellow
			}

			bannerStr := result.Banner
			// 如果返回的结果太长，强制截断，保卫表格队列
			if len(bannerStr) > 50 {
				bannerStr = bannerStr[:47] + "..."
			}

			fmt.Printf("[+] %-15s %5d/%-3s %-10s %s%s%s  %-12s %s\n",
				result.IPStr,
				result.Port,
				protoStr,
				result.Method,
				stateColor, result.State, ColorReset,
				serviceColor+result.Service+ColorReset,
				ColorBlue+bannerStr+ColorReset)
		}

		aggregator.Add(result)

		// ----------------------------------------------------
		// 磁盘持久化：SQLite (钩子调用)
		// ----------------------------------------------------
		saveToSQLiteHook(result, protoStr)
	}

	report := aggregator.Build(GetRunMetadata(), time.Now())
	if conf.GlobalOps.IsOutputFile && conf.GlobalOps.OutputFile != "" {
		if err := WritePortraitReport(conf.GlobalOps.OutputFile, conf.GlobalOps.OutputFormat, report); err != nil {
			fmt.Printf("[!] 无法写入聚合画像文件: %v\n", err)
		}
	}

	closeSQLiteHook()

	fmt.Println("============================")
	fmt.Print(renderPortraitPerformanceSummary(report.Performance))
	fmt.Println("[Persister] 终端回显完毕，所有持久化落盘队列已清空，安全退出。")

	// 敲响最后一记下班铃声！允许 main 函数彻底退出。
	close(PersistDone)
}
