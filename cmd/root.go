package cmd

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/core"
	"Going_Scan/pkg/l7"
	"Going_Scan/pkg/routing"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
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
	Example: `  goscan scan 192.168.1.1 -p 80,443 --syn
  goscan scan 192.168.1.0/24 -p 1-1000 --max-rate 1000
  goscan scan 10.0.0.1 --top-ports 50 --syn --udp -V`,
	RunE: runScan,
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
	f.BoolVarP(&conf.GlobalOps.FastScan, "fast", "F", false, "Use the bundled top 100 ports")
	f.IntVar(&conf.GlobalOps.TopPort, "top-ports", 0, "Scan the first <number> bundled common ports (max 100)")
	f.StringVarP(&conf.GlobalOps.OutputFile, "output", "o", "", "Write the aggregated scan portrait to a file")
	f.StringVar(&conf.GlobalOps.OutputFormat, "output-format", "", "Output portrait format: json or yaml")
	f.StringVar(&conf.GlobalOps.UAMDBPath, "uam-db", "", "Write observations, claims, and projections into the UAM SQLite database at this path")
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

func runScan(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("target IP or CIDR is required")
	}
	conf.GlobalOps.InputS = append([]string(nil), args...)

	if err := validateUnsupportedOptions(); err != nil {
		return err
	}

	ports, portMessage, err := resolvePorts()
	if err != nil {
		return err
	}
	fmt.Println(portMessage)

	scanProfiles, err := resolveScanProfiles()
	if err != nil {
		return err
	}
	fmt.Printf("[*] L4 scan profiles: %s\n", describeScanProfiles(scanProfiles))

	if err := resolveOutputConfig(); err != nil {
		return err
	}
	if conf.GlobalOps.IsOutputFile {
		fmt.Printf("[*] Aggregated portrait output: %s (%s)\n", conf.GlobalOps.OutputFile, conf.GlobalOps.OutputFormat)
	}
	if strings.TrimSpace(conf.GlobalOps.UAMDBPath) != "" {
		fmt.Printf("[*] UAM SQLite output: %s\n", conf.GlobalOps.UAMDBPath)
	}

	core.SetRunMetadata(core.RunMetadata{
		Command:      strings.Join(os.Args, " "),
		Targets:      append([]string(nil), conf.GlobalOps.InputS...),
		Ports:        append([]int(nil), ports...),
		Profiles:     profileNames(scanProfiles),
		ServiceScan:  conf.GlobalOps.Servicescan,
		OutputFile:   conf.GlobalOps.OutputFile,
		OutputFormat: conf.GlobalOps.OutputFormat,
	})

	if err := routing.InitRouter(); err != nil {
		return fmt.Errorf("routing initialization failed: %w", err)
	}

	fmt.Println("[*] Starting Going_Scan V2 Engine...")

	routeInfo := routing.GetDefaultInterface()
	if routeInfo == nil {
		return fmt.Errorf("无法获取本机默认网络接口")
	}
	core.InitUAMHook()
	go core.RunResultPersister()
	localIPStr := routeInfo.SrcIP.String()
	deviceName := routeInfo.DeviceName

	pcapHandle, err := core.InitPcap(deviceName, localIPStr)
	if err != nil {
		return fmt.Errorf("pcap 初始化失败 (请确认是否具有 root/管理员权限): %w", err)
	}
	defer pcapHandle.Close()

	ipIterator, err := conf.GlobalOps.GetTargetIterator()
	if err != nil {
		return fmt.Errorf("IP 解析失败: %w", err)
	}
	conf.ApplyTimingTemplate()
	generator := core.NewTaskGenerator(ipIterator, ports, scanProfiles)

	engine := core.NewEngine(pcapHandle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if conf.GlobalOps.Servicescan {
		l7.InitNmapParser()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] 捕获到手动中断信号 (Ctrl+C)，正在安全回收探针...")
		cancel()
	}()

	totalTasks := estimateTotalTasks(ipIterator.Count(), len(ports), len(scanProfiles))
	core.InitMetrics(totalTasks)
	engine.Run(ctx, generator)
	<-core.PersistDone

	fmt.Println("[*] 完美收工！")
	fmt.Println("[*] Scan completed.")
	return nil
}

// Execute 执行入口
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func estimateTotalTasks(targetCount uint64, portCount int, profileCount int) int64 {
	total := int64(targetCount) * int64(portCount) * int64(profileCount)
	if !conf.GlobalOps.SkipHostDiscovery {
		total += int64(targetCount) * int64(core.DefaultHostDiscoveryProfileCount())
	}
	return total
}

func validateUnsupportedOptions() error {
	var unsupported []string

	if conf.GlobalOps.Connectscan {
		unsupported = append(unsupported, "--connect")
	}

	if conf.GlobalOps.Oscan {
		unsupported = append(unsupported, "--osscan")
	}
	if conf.GlobalOps.Ipprotscan {
		unsupported = append(unsupported, "--protocol")
	}
	if conf.GlobalOps.IdleProxy != "" || conf.GlobalOps.Idlescan {
		unsupported = append(unsupported, "--zombie")
	}
	if conf.GlobalOps.Device != "" {
		unsupported = append(unsupported, "--interface")
	}
	if conf.GlobalOps.SpoofIP != "" {
		unsupported = append(unsupported, "--spoof-ip")
	}
	if conf.GlobalOps.SourcePort != 0 {
		unsupported = append(unsupported, "--source-port")
	}
	if conf.GlobalOps.FragScan {
		unsupported = append(unsupported, "--fragment")
	}
	if conf.GlobalOps.BadSum {
		unsupported = append(unsupported, "--badsum")
	}
	if conf.GlobalOps.DataLength > 0 {
		unsupported = append(unsupported, "--data-length")
	}
	if conf.GlobalOps.NumDecoys > 0 {
		unsupported = append(unsupported, "--decoys")
	}
	if conf.GlobalOps.DefeatRSTRateLimit {
		unsupported = append(unsupported, "--defeat-rst-ratelimit")
	}

	if len(unsupported) == 0 {
		return nil
	}

	sort.Strings(unsupported)
	return fmt.Errorf("这些参数当前还没有接入 V2 引擎，请先不要混用: %s", strings.Join(unsupported, ", "))
}

func resolvePorts() ([]int, string, error) {
	modeCount := 0
	if conf.GlobalOps.PortStr != "" {
		modeCount++
	}
	if conf.GlobalOps.FastScan {
		modeCount++
	}
	if conf.GlobalOps.TopPort > 0 {
		modeCount++
	}
	if modeCount > 1 {
		return nil, "", fmt.Errorf("-p, -F, --top-ports 只能选择一种端口输入方式")
	}

	switch {
	case conf.GlobalOps.PortStr != "":
		ports, err := parsePorts(conf.GlobalOps.PortStr)
		if err != nil {
			return nil, "", err
		}
		return ports, fmt.Sprintf("[*] Scanning %d explicitly selected ports...", len(ports)), nil
	case conf.GlobalOps.FastScan:
		ports := append([]int(nil), core.TopPorts...)
		return ports, fmt.Sprintf("[*] Fast scan mode enabled (bundled top %d ports)...", len(ports)), nil
	case conf.GlobalOps.TopPort > 0:
		if conf.GlobalOps.TopPort > len(core.TopPorts) {
			return nil, "", fmt.Errorf("--top-ports 在当前构建中最多支持 %d 个内置端口", len(core.TopPorts))
		}
		ports := append([]int(nil), core.TopPorts[:conf.GlobalOps.TopPort]...)
		return ports, fmt.Sprintf("[*] Scanning bundled top %d ports...", len(ports)), nil
	default:
		ports := append([]int(nil), core.TopPorts...)
		return ports, fmt.Sprintf("[*] No port specified, using bundled top %d ports...", len(ports)), nil
	}
}

func resolveScanProfiles() ([]core.ScanProfile, error) {
	profiles := make([]core.ScanProfile, 0, 4)
	if conf.GlobalOps.Synscan {
		profiles = append(profiles, core.ScanProfile{
			Name:      "tcp-syn",
			Protocol:  syscall.IPPROTO_TCP,
			ScanFlags: core.FlagSYN,
			ScanKind:  core.ScanKindTCPSYN,
		})
	}
	if conf.GlobalOps.Ackscan {
		profiles = append(profiles, core.ScanProfile{
			Name:      "tcp-ack",
			Protocol:  syscall.IPPROTO_TCP,
			ScanFlags: core.FlagACK,
			ScanKind:  core.ScanKindTCPACK,
		})
	}
	if conf.GlobalOps.Windowscan {
		profiles = append(profiles, core.ScanProfile{
			Name:      "tcp-window",
			Protocol:  syscall.IPPROTO_TCP,
			ScanFlags: core.FlagACK,
			ScanKind:  core.ScanKindTCPWINDOW,
		})
	}
	if conf.GlobalOps.Udpscan {
		profiles = append(profiles, core.ScanProfile{
			Name:     "udp",
			Protocol: syscall.IPPROTO_UDP,
			ScanKind: core.ScanKindUDP,
		})
	}
	if len(profiles) == 0 {
		profiles = core.DefaultPortScanProfiles()
	}
	return profiles, nil
}

func describeScanProfiles(profiles []core.ScanProfile) string {
	return strings.Join(profileNames(profiles), ", ")
}

func profileNames(profiles []core.ScanProfile) []string {
	names := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		names = append(names, profile.Name)
	}
	return names
}

func resolveOutputConfig() error {
	conf.GlobalOps.IsOutputFile = conf.GlobalOps.OutputFile != ""
	if !conf.GlobalOps.IsOutputFile {
		if conf.GlobalOps.OutputFormat != "" {
			return fmt.Errorf("--output-format 需要与 --output 一起使用")
		}
		return nil
	}

	format := strings.ToLower(strings.TrimSpace(conf.GlobalOps.OutputFormat))
	if format == "" {
		switch strings.ToLower(filepath.Ext(conf.GlobalOps.OutputFile)) {
		case ".yaml", ".yml":
			format = "yaml"
		case ".json":
			format = "json"
		default:
			format = "json"
		}
	}

	switch format {
	case "json", "yaml":
		conf.GlobalOps.OutputFormat = format
		return nil
	default:
		return fmt.Errorf("不支持的输出格式 %q，仅支持 json 或 yaml", conf.GlobalOps.OutputFormat)
	}
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
	sort.Ints(ports)

	return ports, nil
}
