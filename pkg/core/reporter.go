package core

import (
	"context"
	"fmt"
	"syscall"

	"Going_Scan/pkg/util"
)

// ScanResult 是未来横向拓展的核心数据结构
type ScanResults struct {
	IP       uint32
	Port     uint16
	Protocol uint8  // TCP, UDP, ICMP
	State    string // "Open", "Closed", "Filtered"

	// 预留给未来重装步兵 (服务指纹探测) 使用的字段
	Service string
	OS      string
	Banner  string
}

// ResultStream 全局异步结果流
var ResultStreams = make(chan ScanResult, 10000)

// StartReporter 启动后台结果消费引擎
func StartReporter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// 消费完管道中剩余的数据后退出
			for len(ResultStream) > 0 {
				res := <-ResultStream
				printResult(res)
			}
			return
		case res := <-ResultStream:
			printResult(res)
			// TODO: 未来在这里将 res 转换为 JSON 格式，通过 WebSocket 发送给 Web 前端
			// WebUI.Broadcast(res.ToJSON())
		}
	}
}

func printResult(res ScanResult) {
	ipStr := util.Uint32ToIP(res.IP).String()
	protoStr := "UNKNOWN"

	switch res.Protocol {
	case syscall.IPPROTO_TCP:
		protoStr = "TCP"
	case syscall.IPPROTO_UDP:
		protoStr = "UDP"
	case 1:
		protoStr = "ICMP"
	}

	if res.State == "open" {
		// 使用特殊的颜色或前缀标识重要发现
		fmt.Printf("[+] Discovered Open Port: %s:%d/%s\n", ipStr, res.Port, protoStr)
	}
}
