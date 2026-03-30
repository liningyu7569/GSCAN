package core

import (
	"context"
	"fmt"
	"sync/atomic"
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
			printSummary()
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
