package l7

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// 全局静态缓存
var (
	CachedNullProbe    *Probe
	CachedGenericProbe *Probe
)

func CacheCommonProbes() {
	for _, p := range GlobalProbes {
		if p.Name == "NULL" {
			CachedNullProbe = p
		} else if p.Name == "GetRequest" {
			CachedGenericProbe = p
		}
	}
}

// IdentifyService 核心逻辑 (加入最高价值遗留物机制)
func IdentifyService(ip string, port uint16, protocol uint8, buf *[]byte) (service string, banner string) {
	targetAddr := fmt.Sprintf("%s:%d", ip, port)
	targetedProbes := PortProbeIndex[int(port)]

	network := "tcp"
	if protocol == syscall.IPPROTO_UDP {
		network = "udp"
	}

	// 用于记录所有探针尝试中，服务器返回的最长的一段数据
	var bestRawData []byte

	// 1. 尝试 NULL 探针
	service, banner, raw := tryProbe(network, targetAddr, CachedNullProbe, buf)
	if service != "" {
		return service, banner
	}
	if len(raw) > len(bestRawData) {
		bestRawData = append([]byte{}, raw...) // 拷贝保存
	}

	// 2. 尝试针对性探针
	for _, probe := range targetedProbes {
		if probe.Protocol != "TCP" && network == "tcp" {
			continue
		}
		if probe.Protocol != "UDP" && network == "udp" {
			continue
		}

		service, banner, raw = tryProbe(network, targetAddr, probe, buf)
		if service != "" {
			return service, banner
		}
		if len(raw) > len(bestRawData) {
			bestRawData = append([]byte{}, raw...)
		}
	}

	// 3. 通用后备探针 (HTTP GET)
	if len(targetedProbes) == 0 && network == "tcp" {
		service, banner, raw = tryProbe(network, targetAddr, CachedGenericProbe, buf)
		if service != "" {
			return service, banner
		}
		if len(raw) > len(bestRawData) {
			bestRawData = append([]byte{}, raw...)
		}
	}

	// 4. 彻底未命中 (unknown 兜底处理)
	// 虽然正则没认出来，但如果服务器吐了数据，我们把它洗干净展示出来！
	if len(bestRawData) > 0 {
		return "unknown", extractSafeBanner(bestRawData)
	}

	return "unknown", ""
}

// tryProbe 修改返回值：多返回一个 []byte (本次读到的原始数据)
func tryProbe(network string, targetAddr string, probe *Probe, buf *[]byte) (string, string, []byte) {
	if probe == nil {
		return "", "", nil
	}

	conn, err := net.DialTimeout(network, targetAddr, 2*time.Second)
	if err != nil {
		return "", "", nil
	}
	defer conn.Close()

	readTimeout := 3 * time.Second
	if len(probe.Payload) > 0 {
		readTimeout = 2 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(readTimeout))

	if len(probe.Payload) > 0 {
		if _, err := conn.Write(probe.Payload); err != nil {
			return "", "", nil
		}
	}

	n, err := conn.Read(*buf)
	if n <= 0 {
		return "", "", nil
	}

	receivedData := (*buf)[:n]

	// 执行正则匹配
	for _, rule := range probe.Matches {
		groups := rule.Pattern.FindSubmatch(receivedData)
		if groups != nil {
			versionStr := buildVersionInfo(rule, groups)

			// 如果模板没提取出信息，使用明文兜底
			if versionStr == "" {
				// 【核心防乱码拦截】绝不对二进制协议进行暴力字符提取！
				if !isBinaryProtocol(rule.Service) {
					versionStr = extractSafeBanner(receivedData)
				}
			}
			return rule.Service, versionStr, receivedData
		}
	}

	return "", "", receivedData
}

// isBinaryProtocol 判定是否为常见的二进制协议，防止终端乱码
func isBinaryProtocol(service string) bool {
	switch service {
	case "ssl", "tls", "msrpc", "smb", "rdp", "mongodb", "mysql":
		return true
	default:
		return false
	}
}

// buildVersionInfo 组装提取的模板信息
func buildVersionInfo(rule MatchRule, groups [][]byte) string {
	var parts []string
	if rule.Product != "" {
		parts = append(parts, expandGroup(rule.Product, groups))
	}
	if rule.Version != "" {
		parts = append(parts, expandGroup(rule.Version, groups))
	}
	if rule.Info != "" {
		parts = append(parts, "("+expandGroup(rule.Info, groups)+")")
	}
	return strings.Join(parts, " ")
}

func expandGroup(template string, groups [][]byte) string {
	res := template
	for i := 1; i < len(groups); i++ {
		placeholder := fmt.Sprintf("$%d", i)
		res = strings.ReplaceAll(res, placeholder, string(groups[i]))
	}
	return res
}

// extractSafeBanner 清洗乱码，极致压缩空白符
func extractSafeBanner(data []byte) string {
	// 剔除所有非 ASCII 可见字符
	var result []rune
	for _, r := range string(data) {
		// 允许可见字符和常用空白符
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			result = append(result, r)
		}
	}

	// 使用 strings.Fields 完美解决多余的空格、换行符嵌套问题
	// 它会将 "HTTP/1.1 200 OK \r\n Server: nginx" 压缩为 "HTTP/1.1 200 OK Server: nginx"
	resStr := strings.Join(strings.Fields(string(result)), " ")

	if len(resStr) > 55 {
		resStr = resStr[:52] + "..."
	}
	return resStr
}
