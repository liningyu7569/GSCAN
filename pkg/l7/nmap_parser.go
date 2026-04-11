package l7

import (
	_ "embed"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed nmap-service-probes
var rawNmapProbes string

var (
	hexEscapeRe      = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	substMacroRe     = regexp.MustCompile(`\$SUBST\((\d+),\s*"((?:\\.|[^"])*)",\s*"((?:\\.|[^"])*)"\)`)
	intMacroRe       = regexp.MustCompile(`\$I\((\d+),\s*"([<>])"\)`)
	printableMacroRe = regexp.MustCompile(`\$P\((\d+)\)`)
	groupMacroRe     = regexp.MustCompile(`\$(\d+)`)
)

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
	CPEs     []string
}

// Probe 探针定义，增加了智能选择与后备机制
type Probe struct {
	Protocol string
	Name     string
	Payload  []byte
	Sequence int

	// 端口偏好 (原样保留，用于生成全局快速索引)
	Ports    []int
	SSLPorts []int
	Fallback string // 若该探针失败，回退到哪个探针的名称
	Rarity   int

	TotalWait time.Duration

	Matches     []MatchRule
	SoftMatches []MatchRule
}

// GlobalProbes 存放所有探针
var GlobalProbes []*Probe

// ProbeNameIndex 供 fallback 和通用探针调度使用
var ProbeNameIndex = make(map[string]*Probe)

// PortProbeIndex 核心优化：O(1) 复杂度的探针调度字典
// L7 收到端口时，查这个字典就能瞬间知道该首发哪些探针
var PortProbeIndex = make(map[int][]*Probe)

// ---------------------------------------------------------
// 解析引擎核心 (包含极强健壮性的解析逻辑)
// ---------------------------------------------------------

func InitNmapParser() {
	fmt.Println("[L7-Parser] 引擎点火：正在深度编译 Nmap 指纹库...")

	resetProbeRegistry()
	loadNmapProbes(rawNmapProbes)
	buildPortIndex()
	CacheCommonProbes()

	fmt.Printf("[L7-Parser] 编译完成！载入探针: %d | 成功编译正则: %d | 舍弃不兼容正则: %d\n",
		parserStats.total, parserStats.matches, parserStats.skipped)
}

var parserStats struct{ total, matches, skipped int }

func resetProbeRegistry() {
	GlobalProbes = nil
	ProbeNameIndex = make(map[string]*Probe)
	PortProbeIndex = make(map[int][]*Probe)
	CachedTCPNullProbe = nil
	CachedTCPGenericProbe = nil
	CachedTCPGenericLinesProbe = nil
	parserStats = struct{ total, matches, skipped int }{}
}

func loadNmapProbes(raw string) {
	lines := strings.Split(raw, "\n")
	var currentProbe *Probe

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 1. 解析 Probe
		if strings.HasPrefix(line, "Probe ") {
			parts := strings.SplitN(line, " ", 4)
			if len(parts) < 4 {
				parserStats.skipped++
				continue
			}
			currentProbe = &Probe{
				Protocol: parts[1],
				Name:     parts[2],
				Payload:  parseNmapPayload(parts[3]),
				Sequence: parserStats.total,
			}
			GlobalProbes = append(GlobalProbes, currentProbe)
			ProbeNameIndex[currentProbe.Name] = currentProbe
			parserStats.total++
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
		if strings.HasPrefix(line, "rarity ") {
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "rarity "))); err == nil && value > 0 {
				currentProbe.Rarity = value
			}
			continue
		}
		if strings.HasPrefix(line, "totalwaitms ") {
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "totalwaitms "))); err == nil && value > 0 {
				currentProbe.TotalWait = time.Duration(value) * time.Millisecond
			}
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
				parserStats.skipped++
				continue
			}

			serviceName := matchStr[:firstSpace]
			remainder := matchStr[firstSpace+1:]

			if !strings.HasPrefix(remainder, "m") {
				parserStats.skipped++
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
				parserStats.skipped++
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
				parserStats.skipped++
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
			parserStats.matches++
		}
	}
}

// ---------------------------------------------------------
// 辅助与增强函数 (Robustness Tools)
// ---------------------------------------------------------

// parseVersionInfo 解析版本信息元数据
func parseVersionInfo(rule *MatchRule, infoStr string) {
	for i := 0; i < len(infoStr); {
		for i < len(infoStr) && infoStr[i] == ' ' {
			i++
		}
		if i >= len(infoStr) {
			break
		}

		key, keyLen := versionInfoKey(infoStr[i:])
		if key == "" {
			i++
			continue
		}
		if i+keyLen >= len(infoStr) {
			break
		}

		delim := infoStr[i+keyLen]
		value, next, ok := readDelimitedToken(infoStr, i+keyLen+1, delim)
		if !ok {
			break
		}

		switch key {
		case "p":
			rule.Product = value
		case "v":
			rule.Version = value
		case "i":
			rule.Info = value
		case "h":
			rule.Hostname = value
		case "o", "O":
			rule.OS = value
		case "d":
			rule.Device = value
		case "cpe":
			rule.CPEs = append(rule.CPEs, value)
		}

		i = next
	}
}

func versionInfoKey(s string) (string, int) {
	switch {
	case strings.HasPrefix(s, "cpe:"):
		return "cpe", len("cpe:")
	case len(s) > 0:
		switch s[0] {
		case 'p', 'v', 'i', 'h', 'o', 'O', 'd':
			return string(s[0]), 1
		}
	}
	return "", 0
}

func readDelimitedToken(s string, start int, delim byte) (string, int, bool) {
	escaped := false
	for i := start; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == delim {
			return s[start:i], i + 1, true
		}
	}
	return "", len(s), false
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
			appendIndexedProbe(port, probe)
		}
		for _, port := range probe.SSLPorts {
			appendIndexedProbe(port, probe)
		}
	}
}

func appendIndexedProbe(port int, probe *Probe) {
	existing := PortProbeIndex[port]
	for _, item := range existing {
		if item == probe {
			return
		}
	}
	PortProbeIndex[port] = append(existing, probe)
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
	return []byte(decodeEscapedText(raw))
}

func decodeEscapedText(raw string) string {
	raw = hexEscapeRe.ReplaceAllStringFunc(raw, func(hexStr string) string {
		val, _ := strconv.ParseUint(hexStr[2:], 16, 8)
		return string([]byte{byte(val)})
	})
	replacer := strings.NewReplacer(
		"\\r", "\r",
		"\\n", "\n",
		"\\t", "\t",
		"\\0", "\x00",
		"\\\"", "\"",
		"\\\\", "\\",
	)
	return replacer.Replace(raw)
}

func expandTemplate(template string, groups [][]byte) string {
	if template == "" {
		return ""
	}

	expanded := substMacroRe.ReplaceAllStringFunc(template, func(match string) string {
		parts := substMacroRe.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		group := templateGroup(parts[1], groups)
		if group == nil {
			return ""
		}
		oldVal := decodeEscapedText(parts[2])
		newVal := decodeEscapedText(parts[3])
		return strings.ReplaceAll(string(group), oldVal, newVal)
	})

	expanded = intMacroRe.ReplaceAllStringFunc(expanded, func(match string) string {
		parts := intMacroRe.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		group := templateGroup(parts[1], groups)
		if len(group) == 0 {
			return ""
		}
		return formatUnsignedGroup(group, parts[2])
	})

	expanded = printableMacroRe.ReplaceAllStringFunc(expanded, func(match string) string {
		parts := printableMacroRe.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		return sanitizePrintableText(templateGroup(parts[1], groups), 0)
	})

	expanded = groupMacroRe.ReplaceAllStringFunc(expanded, func(match string) string {
		parts := groupMacroRe.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		return string(templateGroup(parts[1], groups))
	})

	return strings.TrimSpace(expanded)
}

func templateGroup(indexText string, groups [][]byte) []byte {
	index, err := strconv.Atoi(indexText)
	if err != nil || index <= 0 || index >= len(groups) {
		return nil
	}
	return groups[index]
}

func formatUnsignedGroup(group []byte, order string) string {
	if len(group) == 0 {
		return ""
	}

	data := append([]byte(nil), group...)
	if order == "<" {
		for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
			data[left], data[right] = data[right], data[left]
		}
	}

	value := new(big.Int).SetBytes(data)
	return value.String()
}
