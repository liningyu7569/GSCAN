package cmd

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/routing"
	"Going_Scan/pkg/scanner"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// rootCmd 代表基础命令
var rootCmd = &cobra.Command{
	Use:   "goscan",
	Short: "GoScan is a high-performance network scanner",
	Long:  `GoScan is a fast network scanner written in Go, inspired by Nmap.`,
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

		// 2. 端口解析逻辑
		// 优先级: PortStr (-p) > FastScan (-F) > TopPorts (--top-ports) > Default (1-1000)
		var ports []int
		var err error

		if conf.GlobalOps.PortStr != "" {
			// 解析 -p "80,443" 或 "1-100" (这里简化处理，假设是逗号分隔)
			// 实际项目中建议实现一个更复杂的 ParsePortRange 函数
			ports, err = parsePorts(conf.GlobalOps.PortStr)
			if err != nil {
				fmt.Printf("Invalid port specification: %v\n", err)
				os.Exit(1)
			}
		} else if conf.GlobalOps.FastScan {
			// -F: 扫描 Top 100 端口 (这里仅作示例，需定义 Top100 列表)
			fmt.Println("Fast scan mode enabled (scanning top 100 ports)...")
			ports = make([]int, 100) // 占位
			for i := 0; i < 100; i++ {
				ports[i] = i + 1
			}
		} else if conf.GlobalOps.TopPort > 0 {
			fmt.Printf("Scanning top %d ports...\n", conf.GlobalOps.TopPort)
			// 需要实现 TopPort 生成逻辑
			ports = []int{80, 443} // 占位
		} else {
			// 默认扫描
			fmt.Println("No port specified, scanning default 1000 ports...")
			ports = []int{80, 443, 22, 21} // 占位
		}

		// 3. 扫描模式互斥/默认处理
		// 如果用户没指定任何扫描方式，默认使用 TCP SYN (-sS) (如果是 root) 或 Connect (-sT)
		if !conf.GlobalOps.Synscan && !conf.GlobalOps.Connectscan && !conf.GlobalOps.Udpscan &&
			!conf.GlobalOps.Ackscan && !conf.GlobalOps.Windowscan && !conf.GlobalOps.Idlescan {
			// 这里简单默认为 SYN
			conf.GlobalOps.Synscan = true
		}

		// 4. 处理 Idle Scan
		// 如果设置了代理地址，自动开启 IdleScan 标志
		if conf.GlobalOps.IdleProxy != "" {
			conf.GlobalOps.Idlescan = true
		}

		// 5. 初始化路由和环境
		err = routing.InitRouter()
		if err != nil {
			fmt.Printf("Routing initialization failed: %v\n", err)
			os.Exit(1)
		}

		// 6. 初始化全局端口池并启动扫描
		// 注意：这里的逻辑应该根据 conf.GlobalOps 自动决定初始化哪些协议
		// 建议 scanner.Run() 内部去读取 GlobalOps，而不是在这里手动 if-else

		fmt.Println("Starting GoScan...")

		// 示例：传递端口给底层
		// 实际应该调用 scanner.NewScanner(conf.GlobalOps).Run()
		if conf.GlobalOps.Synscan || conf.GlobalOps.Connectscan || conf.GlobalOps.Ackscan || conf.GlobalOps.Windowscan {
			scanner.GlobalPorts.Initialize(ports, scanner.ProtocolTCP)
		}
		if conf.GlobalOps.Udpscan {
			scanner.GlobalPorts.Initialize(ports, scanner.ProtocolUDP)
		}

		// 启动核心引擎 (假设有这个入口)
		scanner.Start()
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
func parsePorts(s string) ([]int, error) {
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
