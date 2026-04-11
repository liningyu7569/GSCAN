package l7

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

// 全局静态缓存
var (
	CachedTCPNullProbe         *Probe
	CachedTCPGenericProbe      *Probe
	CachedTCPGenericLinesProbe *Probe
)

func CacheCommonProbes() {
	for _, p := range GlobalProbes {
		if p.Name == "NULL" {
			CachedTCPNullProbe = p
		} else if p.Name == "GetRequest" {
			CachedTCPGenericProbe = p
		} else if p.Name == "GenericLines" {
			CachedTCPGenericLinesProbe = p
		}
	}
}

// IdentifyService 核心逻辑。只在协议内选择候选探针，并接入 sslports/fallback。
func IdentifyService(ip string, port uint16, protocol uint8, buf *[]byte) Fingerprint {
	targetAddr := fmt.Sprintf("%s:%d", ip, port)
	network, ok := protocolToNetwork(protocol)
	if !ok {
		return Fingerprint{Service: "unknown"}
	}

	candidates := selectCandidateProbes(port, protocol)
	if len(candidates) == 0 {
		return Fingerprint{Service: "unknown"}
	}

	// 用于记录所有探针尝试中，服务器返回的最长的一段数据
	var bestRawData []byte

	for _, probe := range candidates {
		fp, raw := tryProbe(network, targetAddr, probe, buf)
		if fp.Service != "" {
			return fp
		}
		if len(raw) > len(bestRawData) {
			bestRawData = append(bestRawData[:0], raw...)
		}
	}

	// 彻底未命中 (unknown 兜底处理)
	// 虽然正则没认出来，但如果服务器吐了数据，我们把它洗干净展示出来！
	if len(bestRawData) > 0 {
		return Fingerprint{
			Service: "unknown",
			Banner:  extractSafeBanner(bestRawData),
		}
	}

	return Fingerprint{Service: "unknown"}
}

func protocolToNetwork(protocol uint8) (string, bool) {
	switch protocol {
	case syscall.IPPROTO_TCP:
		return "tcp", true
	case syscall.IPPROTO_UDP:
		return "udp", true
	default:
		return "", false
	}
}

func selectCandidateProbes(port uint16, protocol uint8) []*Probe {
	probeProtocol, ok := probeProtocolName(protocol)
	if !ok {
		return nil
	}

	candidates := make([]*Probe, 0, 8)
	seen := make(map[string]struct{})

	if probeProtocol == "TCP" {
		appendCandidateProbe(&candidates, seen, CachedTCPNullProbe, probeProtocol)
	}

	targeted := orderedPortProbes(port, probeProtocol)
	hadTargeted := len(targeted) > 0
	for _, probe := range targeted {
		appendProbeWithFallbacks(&candidates, seen, probe, probeProtocol)
	}

	if probeProtocol == "TCP" && !hadTargeted {
		appendProbeWithFallbacks(&candidates, seen, CachedTCPGenericLinesProbe, probeProtocol)
		appendProbeWithFallbacks(&candidates, seen, CachedTCPGenericProbe, probeProtocol)
	}

	return candidates
}

func orderedPortProbes(port uint16, protocol string) []*Probe {
	raw := PortProbeIndex[int(port)]
	if len(raw) == 0 {
		return nil
	}

	targeted := make([]*Probe, 0, len(raw))
	for _, probe := range raw {
		if probe != nil && probe.Protocol == protocol {
			targeted = append(targeted, probe)
		}
	}

	sort.SliceStable(targeted, func(i, j int) bool {
		if rarityI, rarityJ := probeRarity(targeted[i]), probeRarity(targeted[j]); rarityI != rarityJ {
			return rarityI < rarityJ
		}
		if scopeI, scopeJ := probeScopeSize(targeted[i]), probeScopeSize(targeted[j]); scopeI != scopeJ {
			return scopeI < scopeJ
		}
		return targeted[i].Sequence < targeted[j].Sequence
	})

	return targeted
}

func probeRarity(probe *Probe) int {
	if probe == nil || probe.Rarity <= 0 {
		return 5
	}
	return probe.Rarity
}

func probeScopeSize(probe *Probe) int {
	if probe == nil {
		return 1 << 30
	}

	size := len(probe.Ports)
	seen := make(map[int]struct{}, len(probe.Ports))
	for _, port := range probe.Ports {
		seen[port] = struct{}{}
	}
	for _, port := range probe.SSLPorts {
		if _, ok := seen[port]; !ok {
			size++
		}
	}
	if size == 0 {
		return 1 << 30
	}
	return size
}

func probeProtocolName(protocol uint8) (string, bool) {
	switch protocol {
	case syscall.IPPROTO_TCP:
		return "TCP", true
	case syscall.IPPROTO_UDP:
		return "UDP", true
	default:
		return "", false
	}
}

func appendProbeWithFallbacks(dst *[]*Probe, seen map[string]struct{}, probe *Probe, protocol string) {
	if probe == nil {
		return
	}
	appendCandidateProbe(dst, seen, probe, protocol)
	for _, name := range splitFallbackNames(probe.Fallback) {
		appendProbeWithFallbackByName(dst, seen, name, protocol)
	}
}

func appendProbeWithFallbackByName(dst *[]*Probe, seen map[string]struct{}, name string, protocol string) {
	probe, ok := ProbeNameIndex[name]
	if !ok || probe == nil || probe.Protocol != protocol {
		return
	}
	if _, exists := seen[probe.Name]; exists {
		return
	}
	appendCandidateProbe(dst, seen, probe, protocol)
	for _, fallbackName := range splitFallbackNames(probe.Fallback) {
		appendProbeWithFallbackByName(dst, seen, fallbackName, protocol)
	}
}

func appendCandidateProbe(dst *[]*Probe, seen map[string]struct{}, probe *Probe, protocol string) {
	if probe == nil || probe.Protocol != protocol {
		return
	}
	if _, exists := seen[probe.Name]; exists {
		return
	}
	seen[probe.Name] = struct{}{}
	*dst = append(*dst, probe)
}

func splitFallbackNames(fallback string) []string {
	if fallback == "" {
		return nil
	}

	parts := strings.Split(fallback, ",")
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			names = append(names, part)
		}
	}
	return names
}

// tryProbe 返回命中的结构化指纹，以及本次采集到的原始数据。
func tryProbe(network string, targetAddr string, probe *Probe, buf *[]byte) (Fingerprint, []byte) {
	if probe == nil {
		return Fingerprint{}, nil
	}

	if network == "udp" && len(probe.Payload) == 0 {
		return Fingerprint{}, nil
	}

	dialTimeout := 2 * time.Second
	if probe.TotalWait > 0 && probe.TotalWait < dialTimeout {
		dialTimeout = probe.TotalWait
	}

	conn, err := net.DialTimeout(network, targetAddr, dialTimeout)
	if err != nil {
		return Fingerprint{}, nil
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))

	if len(probe.Payload) > 0 {
		if _, err := conn.Write(probe.Payload); err != nil {
			return Fingerprint{}, nil
		}
	}

	receivedData := readProbeResponse(conn, network, probe, buf)
	if len(receivedData) == 0 {
		return Fingerprint{}, nil
	}

	// 执行正则匹配
	for _, rule := range probe.Matches {
		groups := rule.Pattern.FindSubmatch(receivedData)
		if groups != nil {
			return buildFingerprintFromRule(rule, groups, receivedData), receivedData
		}
	}

	return Fingerprint{}, receivedData
}

func readProbeResponse(conn net.Conn, network string, probe *Probe, buf *[]byte) []byte {
	if buf == nil || len(*buf) == 0 {
		return nil
	}

	waitBudget := probeReadBudget(probe)
	overallDeadline := time.Now().Add(waitBudget)
	idleGap := probeIdleGap(waitBudget)
	total := 0

	for total < len(*buf) {
		readDeadline := overallDeadline
		if total > 0 {
			idleDeadline := time.Now().Add(idleGap)
			if idleDeadline.Before(readDeadline) {
				readDeadline = idleDeadline
			}
		}
		_ = conn.SetReadDeadline(readDeadline)

		n, err := conn.Read((*buf)[total:])
		if n > 0 {
			total += n
			if network == "udp" || total == len(*buf) {
				break
			}
			continue
		}
		if err != nil {
			if total > 0 {
				break
			}
			return nil
		}
	}

	if total == 0 {
		return nil
	}
	return (*buf)[:total]
}

func probeReadBudget(probe *Probe) time.Duration {
	if probe != nil && probe.TotalWait > 0 {
		return probe.TotalWait
	}
	if probe != nil && len(probe.Payload) > 0 {
		return 2 * time.Second
	}
	return 3 * time.Second
}

func probeIdleGap(waitBudget time.Duration) time.Duration {
	gap := waitBudget / 4
	if gap < 200*time.Millisecond {
		return 200 * time.Millisecond
	}
	if gap > 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	return gap
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

// extractSafeBanner 清洗乱码，极致压缩空白符
func extractSafeBanner(data []byte) string {
	return sanitizePrintableText(data, 55)
}

func sanitizePrintableText(data []byte, maxLen int) string {
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

	if maxLen > 0 && len(resStr) > maxLen {
		resStr = resStr[:maxLen-3] + "..."
	}
	return resStr
}
