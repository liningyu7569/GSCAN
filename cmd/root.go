package cmd

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/core"
	"Going_Scan/pkg/routing"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// rootCmd 代表基础命令
var rootCmd = &cobra.Command{
	Use:   "goscan",
	Short: "GoScan is a high-performance network core",
	Long:  `GoScan is a fast network core written in Go, inspired by Nmap.`,
}

// scanCmd 代表扫描命令
var scanCmd = &cobra.Command{
	Use:   "scan [targets]",
	Short: "Run a scan against target hosts",
	Example: `  goscan scan 192.168.1.1 -p 80,443 -sS
  goscan scan 192.168.1.0/24 -p 1-1000 --max-rate 1000
  goscan scan 10.0.0.1 --top-ports 100 -sV`,
	Run: func(cmd *cobra.Command, args []string) {
		// 1. 处理目标输入
		if len(args) > 0 {
			conf.GlobalOps.InputS = args
		} else {
			fmt.Println("Error: Target IP or CIDR is required.")
			fmt.Println("Usage: goscan scan [targets] [flags]")
			os.Exit(1)
		}
		//t := time.Now()
		// 2. 端口解析逻辑 (保留你原有的逻辑)
		var ports []int
		var err error

		if conf.GlobalOps.PortStr != "" {

			ports, err = parsePorts(conf.GlobalOps.PortStr)
			if err != nil {
				fmt.Printf("%s is error for %e \n", conf.GlobalOps.PortStr, err)
			}
			//ports = []int{80, 443, 21, 22, 23, 24} // 占位演示
		} else if conf.GlobalOps.FastScan {
			fmt.Println("[*] Fast scan mode enabled (scanning top 100 ports)...")
			ports = make([]int, 10000)
			for i := 0; i < 10000; i++ {
				ports[i] = i + 1
			}
		} else if conf.GlobalOps.TopPort > 0 {
			fmt.Printf("[*] Scanning top %d ports...\n", conf.GlobalOps.TopPort)
			ports = []int{80, 443} // 占位演示
		} else {
			fmt.Println("[*] No port specified, scanning default ports...")
			ports = []int{80, 443, 22, 21} // 占位演示
		}

		// 3. 扫描模式互斥/默认处理
		if !conf.GlobalOps.Synscan && !conf.GlobalOps.Connectscan && !conf.GlobalOps.Udpscan &&
			!conf.GlobalOps.Ackscan && !conf.GlobalOps.Windowscan && !conf.GlobalOps.Idlescan {
			conf.GlobalOps.Synscan = true
		}

		// 4. 初始化路由和环境
		err = routing.InitRouter()
		if err != nil {
			fmt.Printf("[-] Routing initialization failed: %v\n", err)
			os.Exit(1)
		}

		// =========================================================================
		// 【V2 架构接入开始】: 废弃旧的 GlobalPorts 初始化，全面启用张量引擎
		// =========================================================================

		fmt.Println("[*] Starting Going_Scan V2 Engine...")

		// 5. 获取本机默认出口网卡与 IP (用于 Pcap 监听和构建 BPF 过滤)
		// 这里假设你的 routing 包有获取默认网卡信息的方法
		routeInfo := routing.GetDefaultInterface()
		if routeInfo == nil {
			fmt.Println("[-] 致命错误: 无法获取本机默认网络接口")
			os.Exit(1)
		}
		localIPStr := routeInfo.SrcIP.String()
		deviceName := routeInfo.DeviceName

		// 6. 初始化底层 Pcap 句柄
		pcapHandle, err := core.InitPcap(deviceName, localIPStr)
		if err != nil {
			fmt.Printf("[-] 致命错误: Pcap 初始化失败 (请确认是否具有 root/管理员权限): %v\n", err)
			os.Exit(1)
		}
		defer pcapHandle.Close() // 确保程序退出时释放网卡句柄

		// 7. 初始化目标迭代器
		ipIterator, err := conf.GlobalOps.GetTargetIterator()
		if err != nil {
			fmt.Printf("[-] IP 解析失败: %v\n", err)
			os.Exit(1)
		}
		conf.ApplyTimingTemplate()
		// 8. 创建任务张量生成器 (Task Generator)
		generator := core.NewTaskGenerator(ipIterator, ports)

		// 9. 创建稳态引擎 (Engine)
		// 设置初始并发 CWND 为 1000 (可根据配置动态调整)
		//initialCWND := 1000
		engine := core.NewEngine(pcapHandle)

		// 10. 创建带有取消功能的上下文，并监听系统中断信号 (Ctrl+C)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Println("\n[!] 捕获到手动中断信号 (Ctrl+C)，正在安全回收探针...")
			cancel() // 触发 ctx.Done()，引擎会立刻停止下发新任务
		}()

		totalTasks := int64(ipIterator.Count()) * int64(len(ports))
		core.InitMetrics(totalTasks)
		go core.StartMonitor(ctx)
		go core.StartReporter(ctx)
		// 11. 引擎点火！阻塞等待直到所有任务完成或被中断
		engine.Run(ctx, generator)

		fmt.Println("[*] Scan completed.")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	f := scanCmd.Flags()

	// --- 1. 扫描技术 (Scan Techniques) ---
	f.BoolVarP(&conf.GlobalOps.Synscan, "syn", "s", false, "TCP SYN scan (default for root)")
	f.BoolVar(&conf.GlobalOps.Connectscan, "connect", false, "TCP Connect() scan") // 为了避免冲突，connect 不用短参，或者用 -sT 风格需要自定义解析
	f.BoolVarP(&conf.GlobalOps.Udpscan, "udp", "U", false, "UDP scan")
	f.BoolVarP(&conf.GlobalOps.Ackscan, "ack", "A", false, "TCP ACK scan")
	f.BoolVarP(&conf.GlobalOps.Windowscan, "window", "W", false, "TCP Window scan")
	f.BoolVarP(&conf.GlobalOps.Oscan, "osscan", "O", false, "Enable OS detection")
	f.BoolVarP(&conf.GlobalOps.Servicescan, "service", "V", false, "Probe open ports to determine service/version")
	f.BoolVarP(&conf.GlobalOps.Ipprotscan, "protocol", "Y", false, "IP protocol scan") // Nmap 是 -sO

	// Idle Scan 特殊处理：它需要一个参数
	f.StringVar(&conf.GlobalOps.IdleProxy, "zombie", "", "Idle scan using zombie host (e.g. 192.168.1.5:80)")

	// --- 2. 端口与目标 (Port & Target) ---
	f.StringVarP(&conf.GlobalOps.PortStr, "port", "p", "", "Ports to scan (e.g. 80,443,1-100)")
	f.StringVar(&conf.GlobalOps.ExcludeStr, "exclude", "", "Exclude hosts/networks")
	f.BoolVarP(&conf.GlobalOps.FastScan, "fast", "F", false, "Fast mode - Scan fewer ports than the default scan")
	f.IntVar(&conf.GlobalOps.TopPort, "top-ports", 0, "Scan <number> most common ports")
	f.BoolVarP(&conf.GlobalOps.RandomizeHosts, "randomize-hosts", "", true, "Randomize target scan order")

	// --- 3. 性能与时序 (Timing & Performance) ---
	f.IntVarP(&conf.GlobalOps.TimingLevel, "timing", "T", 3, "Timing template (0-5)")
	f.Float32Var(&conf.GlobalOps.MinPacketSendRate, "min-rate", 0, "Send packets no slower than <number> per second")
	f.Float32Var(&conf.GlobalOps.MaxPacketSendRate, "max-rate", 0, "Send packets no faster than <number> per second")
	f.IntVar(&conf.GlobalOps.MinParallelism, "min-parallelism", 0, "Probe parallelization min operations")
	f.IntVar(&conf.GlobalOps.MaxParallelism, "max-parallelism", 0, "Probe parallelization max operations")
	f.IntVar(&conf.GlobalOps.HostTimeout, "host-timeout", 0, "Give up on target after this long (ms)")
	f.IntVar(&conf.GlobalOps.MaxRetries, "max-retries", 0, "Caps number of port scan probe retransmissions")
	f.IntVar(&conf.GlobalOps.MaxRTTTimeout, "max-rtt-timeout", 0, "Maximum RTT timeout (ms)")

	// --- 4. 防火墙/IDS 规避 (Firewall/IDS Evasion) ---
	f.BoolVarP(&conf.GlobalOps.FragScan, "fragment", "f", false, "Fragment packets")
	f.BoolVar(&conf.GlobalOps.BadSum, "badsum", false, "Send packets with a bogus TCP/UDP/SCTP checksum")
	f.IntVar(&conf.GlobalOps.DataLength, "data-length", 0, "Append random data to sent packets")
	f.StringVarP(&conf.GlobalOps.SpoofIP, "spoof-ip", "S", "", "Spoof source address")
	f.StringVarP(&conf.GlobalOps.Device, "interface", "e", "", "Use specified interface")
	f.IntVarP(&conf.GlobalOps.SourcePort, "source-port", "g", 0, "Use given port number")
	f.IntVar(&conf.GlobalOps.TTL, "ttl", 64, "Set IP time-to-live field")
	f.IntVarP(&conf.GlobalOps.NumDecoys, "decoys", "D", 0, "Number of decoys to use")
	f.BoolVar(&conf.GlobalOps.DefeatRSTRateLimit, "defeat-rst-ratelimit", false, "Ignore RST rate limits")
}

// Execute 执行入口
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// 辅助函数：解析简单的端口字符串
func parsePort(s string) ([]int, error) {
	// 这里只是一个极其简单的实现，实际需要支持 "1-100,200" 这种格式
	parts := strings.Split(s, ",")
	var ints []int
	for _, v := range parts {
		v = strings.TrimSpace(v)
		if strings.Contains(v, "-") {
			// 处理范围 80-90
			rangeParts := strings.Split(v, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", v)
			}
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			for i := start; i <= end; i++ {
				ints = append(ints, i)
			}
		} else {
			// 处理单个端口
			num, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			ints = append(ints, num)
		}
	}
	return ints, nil
}

func parsePorts(s string) ([]int, error) {
	if s == "" {
		return []int{}, nil
	}

	// 使用 set 来自动去重
	portSet := make(map[int]struct{})

	// 分割逗号
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// 处理范围：如 1-1000
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的范围格式: %q", part)
			}

			startStr := strings.TrimSpace(rangeParts[0])
			endStr := strings.TrimSpace(rangeParts[1])

			start, err := strconv.Atoi(startStr)
			if err != nil {
				return nil, fmt.Errorf("起始端口无效 %q: %v", startStr, err)
			}

			end, err := strconv.Atoi(endStr)
			if err != nil {
				return nil, fmt.Errorf("结束端口无效 %q: %v", endStr, err)
			}

			if start < 1 || end < 1 {
				return nil, fmt.Errorf("端口不能小于1: %d-%d", start, end)
			}

			if start > end {
				return nil, fmt.Errorf("范围无效（起点大于终点）: %d-%d", start, end)
			}

			// 建议加上上限保护，防止误输入 1-10000000 导致内存爆炸
			if end-start > 100000 { // 可根据实际场景调整
				return nil, fmt.Errorf("范围过大（%d-%d），超过允许的最大跨度", start, end)
			}

			for p := start; p <= end; p++ {
				portSet[p] = struct{}{}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %q", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号超出范围(1-65535): %d", port)
			}
			portSet[port] = struct{}{}
		}
	}

	// 转为有序切片
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	//sort.Ints(ports)

	return ports, nil
}
