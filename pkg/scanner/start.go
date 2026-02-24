package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/target"
	"fmt"
	"time"
)

// Start 核心启动入口
func Start() {
	// 1. 获取目标迭代器 (从 CIDR/List 解析出 IP)
	iterator, err := conf.GlobalOps.GetTargetIterator()
	if err != nil {
		fmt.Printf("Failed to initialize target iterator: %v\n", err)
		return
	}

	// 2. 初始化主机组生成器
	// 每次处理多少个主机？建议 64-256，取决于并发能力
	// 如果是 Ping 扫描，可以一次几千个
	batchSize := 128
	if conf.GlobalOps.Pingtype {
		batchSize = 4096
	}

	hostGroup := NewHostGroupState(iterator, batchSize)

	fmt.Println("Starting Scan Engine...")
	startTime := time.Now()

	// 3. 主调度循环
	for {
		// A. 获取下一批目标
		targets := hostGroup.GetNextBatch()
		if targets == nil {
			break // 全部完成
		}

		if len(targets) == 0 {
			continue // 这一批虽然有 IP 但全都没路由/死机了，跳过
		}

		fmt.Printf("Scanning batch of %d hosts...\n", len(targets))

		// B. 初始化 USI (UltraScanInfo)
		usi := NewUSI(targets)

		// C. 执行扫描 (阻塞直到完成)
		usi.Run()

		// D. 处理结果 (Output)
		// 目前结果存储在 usi.CompletedHosts 中
		// 我们可以在这里打印，或者把它们汇总到别的地方
		printBatchResults(usi.CompletedHosts)
	}

	duration := time.Since(startTime)
	fmt.Printf("\nScan finished in %.2fs\n", duration.Seconds())
}

// 简单的结果打印 (后续可替换为专用 Output 模块)
func printBatchResults(hosts []*HostScanStats) {
	for _, hss := range hosts {
		t := hss.Target
		fmt.Printf("\nNmap scan report for %s\n", t.TargetIpAddr())
		if t.Status == target.HostUp {
			fmt.Println("Host is up.")
			// 遍历端口状态
			// 这里需要遍历 GlobalPorts.Maps[ProtocolTCP].List
			// 或者 HSS 内部记录的 Open 端口
			// 暂时简单打印 Open 的端口
			// (你需要实现一个方法来获取 Target 中所有 Open 的端口)
			printOpenPorts(t)
		} else {
			fmt.Println("Host seems down.")
		}
	}
}

func printOpenPorts(t *target.Target) {
	if conf.GlobalOps.TCPScan() {
		lookup := t.PortStates[ProtocolTCP]
		var idx int
		state := ""
		for _, idx = range GlobalPorts.Maps[ProtocolTCP].List {
			if lookup[GlobalPorts.Maps[ProtocolTCP].Lookup[idx]] == uint8(target.PortOpen) {
				state = "Open"
				fmt.Println(idx, ":", state)
			}
			if lookup[GlobalPorts.Maps[ProtocolTCP].Lookup[idx]] == uint8(target.PortClosed) {
				state = "Close"
			}

			if lookup[GlobalPorts.Maps[ProtocolTCP].Lookup[idx]] == uint8(target.PortFiltered) {
				state = "Filter"
			}

		}
	}
	if conf.GlobalOps.UDPScan() {

	}
}
