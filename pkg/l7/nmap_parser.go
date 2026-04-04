package l7

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//go:embed nmap-service-probes
var rawNmapProbes string
var versionInfoRe = regexp.MustCompile(`([pvihoOd])/([^/]+)/`)

// ---------------------------------------------------------
// 核心结构体定义 (全面拥抱版本提取与端口索引)
// ---------------------------------------------------------

// MatchRule 匹配规则，全面支持版本信息模板
type MatchRule struct {
	Service string         // 服务分类，如 http, ssh
	Pattern *regexp.Regexp // 预编译的正则表达式

	// 版本与指纹元数据模板 (可能包含 $1, $2 等捕获组)
	Product  string // p/Apache httpd/
	Version  string // v/2.4.41/
	Info     string // i/Ubuntu/
	Hostname string // h/xxx/
	OS       string // o/Linux/
	Device   string // d/router/
}

// Probe 探针定义，增加了智能选择与后备机制
type Probe struct {
	Protocol string
	Name     string
	Payload  []byte

	// 端口偏好 (原样保留，用于生成全局快速索引)
	Ports    []int
	SSLPorts []int
	Fallback string // 若该探针失败，回退到哪个探针的名称

	Matches     []MatchRule
	SoftMatches []MatchRule
}

// GlobalProbes 存放所有探针
var GlobalProbes []*Probe

// PortProbeIndex 核心优化：O(1) 复杂度的探针调度字典
// L7 收到端口时，查这个字典就能瞬间知道该首发哪些探针
var PortProbeIndex = make(map[int][]*Probe)

// ---------------------------------------------------------
// 解析引擎核心 (包含极强健壮性的解析逻辑)
// ---------------------------------------------------------

func InitNmapParser() {
	fmt.Println("[L7-Parser] 引擎点火：正在深度编译 Nmap 指纹库...")

	lines := strings.Split(rawNmapProbes, "\n")
	var currentProbe *Probe

	// 统计指标
	stats := struct{ total, matches, skipped int }{}

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 1. 解析 Probe
		if strings.HasPrefix(line, "Probe ") {
			parts := strings.SplitN(line, " ", 4)
			if len(parts) < 4 {
				stats.skipped++
				continue
			}
			currentProbe = &Probe{
				Protocol: parts[1],
				Name:     parts[2],
				Payload:  parseNmapPayload(parts[3]),
			}
			GlobalProbes = append(GlobalProbes, currentProbe)
			stats.total++
			continue
		}

		if currentProbe == nil {
			continue
		}

		// 2. 解析 ports / sslports (增强版：支持逗号和连字符)
		if strings.HasPrefix(line, "ports ") {
			currentProbe.Ports = parsePorts(strings.TrimPrefix(line, "ports "))
			continue
		}
		if strings.HasPrefix(line, "sslports ") {
			currentProbe.SSLPorts = parsePorts(strings.TrimPrefix(line, "sslports "))
			continue
		}

		// 3. 解析 fallback 指令
		if strings.HasPrefix(line, "fallback ") {
			currentProbe.Fallback = strings.TrimPrefix(line, "fallback ")
			continue
		}

		// 4. 解析 match / softmatch (包含健壮的正则切割与版本提取)
		isMatch := strings.HasPrefix(line, "match ")
		isSoftMatch := strings.HasPrefix(line, "softmatch ")

		if isMatch || isSoftMatch {
			matchStr := line
			if isMatch {
				matchStr = strings.TrimPrefix(matchStr, "match ")
			} else {
				matchStr = strings.TrimPrefix(matchStr, "softmatch ")
			}

			// Nmap 格式: <service> m|<regex>|<flags> [<versioninfo>]
			firstSpace := strings.Index(matchStr, " ")
			if firstSpace == -1 {
				stats.skipped++
				continue
			}

			serviceName := matchStr[:firstSpace]
			remainder := matchStr[firstSpace+1:]

			if !strings.HasPrefix(remainder, "m") {
				stats.skipped++
				continue
			}

			// 健壮切割：寻找闭合分隔符，同时处理被转义的分隔符 (如 \|)
			delimiter := remainder[1]
			endIdx := -1
			for i := 2; i < len(remainder); i++ {
				if remainder[i] == delimiter && remainder[i-1] != '\\' {
					endIdx = i
					break
				}
			}

			if endIdx == -1 {
				// 正则未闭合，语法错误
				fmt.Printf("[!] 解析警告 (行 %d): 正则表达式未闭合\n", lineNum+1)
				stats.skipped++
				continue
			}

			rawRegex := remainder[2:endIdx]

			// 提取 flags 和紧随其后的 versionInfo
			afterRegex := remainder[endIdx+1:]
			afterRegexParts := strings.SplitN(afterRegex, " ", 2)
			flags := afterRegexParts[0]
			versionInfoStr := ""
			if len(afterRegexParts) > 1 {
				versionInfoStr = afterRegexParts[1]
			}

			// 转化为 Go 正则
			goRegexStr := rawRegex
			if strings.Contains(flags, "i") {
				goRegexStr = "(?i)" + goRegexStr
			}
			if strings.Contains(flags, "s") {
				goRegexStr = "(?s)" + goRegexStr
			}

			compiledRegex, err := regexp.Compile(goRegexStr)
			if err != nil {
				// 这是正常的，Nmap 库里有部分 PCRE 高级语法 Go 标准库不支持
				stats.skipped++
				continue
			}

			rule := MatchRule{
				Service: serviceName,
				Pattern: compiledRegex,
			}

			// 解析版本模板 (p/xxx/ v/xxx/)
			if versionInfoStr != "" {
				parseVersionInfo(&rule, versionInfoStr)
			}

			if isMatch {
				currentProbe.Matches = append(currentProbe.Matches, rule)
			} else {
				currentProbe.SoftMatches = append(currentProbe.SoftMatches, rule)
			}
			stats.matches++
		}
	}

	// 5. 构建全局智能端口调度索引 (极大地提升未来 L7 Worker 的运行效率)
	buildPortIndex()

	fmt.Printf("[L7-Parser] 编译完成！载入探针: %d | 成功编译正则: %d | 舍弃不兼容正则: %d\n",
		stats.total, stats.matches, stats.skipped)

	CacheCommonProbes()
}

// ---------------------------------------------------------
// 辅助与增强函数 (Robustness Tools)
// ---------------------------------------------------------

// parseVersionInfo 解析版本信息元数据
func parseVersionInfo(rule *MatchRule, infoStr string) {
	// Nmap 的模板结构为 <标记><定界符><内容><定界符>，例如 p/Apache/ v/2.4/
	// 直接复用全局预编译的正则，极其丝滑
	matches := versionInfoRe.FindAllStringSubmatch(infoStr, -1)

	for _, m := range matches {
		if len(m) == 3 {
			key, val := m[1], m[2]
			switch key {
			case "p":
				rule.Product = val
			case "v":
				rule.Version = val
			case "i":
				rule.Info = val
			case "h":
				rule.Hostname = val
			case "o":
				rule.OS = val
			case "d":
				rule.Device = val
			}
		}
	}
}

// parsePorts 解析 80,443,8000-8010 格式
func parsePorts(portStr string) []int {
	var ports []int
	parts := strings.Split(portStr, ",")
	for _, p := range parts {
		if strings.Contains(p, "-") {
			ranges := strings.Split(p, "-")
			if len(ranges) == 2 {
				start, _ := strconv.Atoi(ranges[0])
				end, _ := strconv.Atoi(ranges[1])
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			port, _ := strconv.Atoi(p)
			if port > 0 {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

// buildPortIndex 构建端口倒排索引，加速 L7 Worker 查询
func buildPortIndex() {
	for _, probe := range GlobalProbes {
		for _, port := range probe.Ports {
			PortProbeIndex[port] = append(PortProbeIndex[port], probe)
		}
	}
}

func parseNmapPayload(qStr string) []byte {
	// [保持原有的十六进制转义解包代码不变]
	// ... (见之前版本的实现)
	if !strings.HasPrefix(qStr, "q") || len(qStr) < 3 {
		return nil
	}
	delim := qStr[1:2]
	parts := strings.Split(qStr[2:], delim)
	if len(parts) == 0 {
		return nil
	}
	raw := parts[0]
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\t", "\t")
	raw = strings.ReplaceAll(raw, "\\0", "\x00")
	re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	raw = re.ReplaceAllStringFunc(raw, func(hexStr string) string {
		val, _ := strconv.ParseUint(hexStr[2:], 16, 8)
		return string([]byte{byte(val)})
	})
	return []byte(raw)
}
