package gping

import (
	"Going_Scan/internal/uam/domain"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var leadingBannerCodePattern = regexp.MustCompile(`^\d{3}[ -]+`)
var versionTokenPattern = regexp.MustCompile(`^\d+(?:\.\d+)+(?:[-._a-zA-Z0-9]+)?$`)

// normalizeProtocol 将协议字符串规范化为 tcp/udp/icmp 或原值
func normalizeProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	default:
		return value
	}
}

// normalizeRoute 将路由名称转为小写并去除空白
func normalizeRoute(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// normalizeMethod 将方法名转为小写并去除空白
func normalizeMethod(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// normalizeVerificationState 将验证状态规范化为 UAM domain 中定义的值
func normalizeVerificationState(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", domain.VerificationNone, domain.VerificationPending, domain.VerificationConfirmed, domain.VerificationOverridden:
		return value
	default:
		return value
	}
}

// stringValue 返回非空字符串值，否则返回 fallback
func stringValue(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// floatPtrValue 将 float64 转为指针，用于 RTT 等可选数值字段
func floatPtrValue(value float64) *float64 {
	v := value
	return &v
}

// marshalExtraJSON 将额外字段 map 序列化为 JSON 字符串
func marshalExtraJSON(extra map[string]any) string {
	if len(extra) == 0 {
		return ""
	}
	raw, err := json.Marshal(extra)
	if err != nil {
		return ""
	}
	return string(raw)
}

// splitHeaderValue 解析 "key:value" 格式的 HTTP 头部字符串
func splitHeaderValue(raw string) (string, string, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("header must look like key:value")
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", fmt.Errorf("header key cannot be empty")
	}
	return key, value, nil
}

// splitVarValue 解析 "key=value" 格式的模板变量字符串
func splitVarValue(raw string) (string, string, error) {
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("var must look like key=value")
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", fmt.Errorf("var key cannot be empty")
	}
	return key, value, nil
}

// resolveHostToIPv4 将主机名或 IP 解析为 IPv4 地址
func resolveHostToIPv4(host string) (string, error) {
	if parsed := net.ParseIP(strings.TrimSpace(host)); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("only IPv4 is supported in the current gping MVP")
	}

	addrs, err := net.LookupIP(strings.TrimSpace(host))
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if v4 := addr.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 record found for %s", host)
}

// splitServerProduct 从 Server 头部解析产品名和版本号（如 "Apache/2.4.41"）
func splitServerProduct(server string) (string, string) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", ""
	}
	token := strings.Fields(server)[0]
	parts := strings.SplitN(token, "/", 2)
	product := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		return product, ""
	}
	return product, strings.TrimSpace(parts[1])
}

// parseBannerProductVersion 从服务 banner 的首行中解析产品名和版本号
func parseBannerProductVersion(banner string) (string, string) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "", ""
	}

	line := firstLine(banner)
	line = leadingBannerCodePattern.ReplaceAllString(line, "")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}

	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return "", ""
	}
	if strings.Contains(tokens[0], "/") {
		return splitServerProduct(tokens[0])
	}

	product := strings.Trim(tokens[0], "[]()")
	version := ""
	if len(tokens) > 1 && versionTokenPattern.MatchString(strings.Trim(tokens[1], "[]()")) {
		version = strings.Trim(tokens[1], "[]()")
	}
	return product, version
}

// firstLine 返回文本的首行（去除换行）
func firstLine(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

// previewText 截断长文本并添加省略号，用于摘要展示
func previewText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
}

// decodeEscapedText 解码转义字符（\\, \r, \n, \t）
func decodeEscapedText(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\`,
		`\r`, "\r",
		`\n`, "\n",
		`\t`, "\t",
	)
	return replacer.Replace(value)
}

// extractHTMLTitle 从 HTML 响应体中提取 <title> 标签内容
func extractHTMLTitle(body string) string {
	if body == "" {
		return ""
	}
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	title := strings.TrimSpace(strings.ReplaceAll(match[1], "\n", " "))
	title = strings.Join(strings.Fields(title), " ")
	return title
}

// buildURLString 根据 scheme、host、port、path 构建完整 URL 字符串
func buildURLString(scheme string, host string, port int, path string) string {
	pathPart, rawQuery := normalizePathAndQuery(path)
	urlHost := host
	if port > 0 && !defaultPortForScheme(scheme, port) {
		urlHost = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return (&url.URL{
		Scheme:   scheme,
		Host:     urlHost,
		Path:     pathPart,
		RawQuery: rawQuery,
	}).String()
}

func normalizePathAndQuery(path string) (string, string) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parts := strings.SplitN(path, "?", 2)
	pathPart := parts[0]
	rawQuery := ""
	if len(parts) == 2 {
		rawQuery = parts[1]
	}
	return pathPart, rawQuery
}

func defaultPortForScheme(scheme string, port int) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return port == 80
	case "https":
		return port == 443
	default:
		return false
	}
}

// cloneHeaders 深拷贝 HTTP 头部 map（可选地过滤敏感字段）
func cloneHeaders(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	return cloneStringMap(src)
}

// cloneStringMap 深拷贝 string->string map
func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

// fileExists 检查指定路径是否为存在的普通文件
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// osReadFile 是对 os.ReadFile 的薄封装，便于测试替换
func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
