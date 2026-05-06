package gping

import (
	"fmt"
	"strconv"
	"strings"
)

// normalizeAdapter 将适配器名称转为小写并去除空白
func normalizeAdapter(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// inferAdapterForMethod 根据方法名自动推断对应的适配器类型
func inferAdapterForMethod(method string) string {
	switch normalizeMethod(method) {
	case "http-head", "http-get", "http-post":
		return "http"
	case "tcp-raw", "icmp-raw":
		return ""
	case "dns-query":
		return "dns"
	case "ftp-banner", "ftp-feat", "ftp-auth-tls":
		return "ftp"
	case "smtp-banner", "smtp-ehlo", "smtp-starttls":
		return "smtp"
	case "redis-ping", "redis-info-server", "redis-info-replication":
		return "redis"
	case "ssh-banner", "ssh-kexinit", "ssh-hostkey":
		return "ssh"
	case "mysql-greeting", "mysql-capabilities", "mysql-starttls":
		return "mysql"
	default:
		return ""
	}
}

// actionUsesURL 判断动作是否通过 HTTP 适配器使用 URL
func actionUsesURL(action ActionUnit) bool {
	return normalizeRoute(action.Route) == "app" && normalizeAdapter(action.Adapter) == "http"
}

// applyActionParams 将 params 中的参数填充到 action 的对应字段
func applyActionParams(action *ActionUnit) {
	if action == nil || len(action.Params) == 0 {
		return
	}
	if action.URL == "" {
		action.URL = stringAny(action.Params["url"])
	}
	if action.Path == "" {
		action.Path = stringAny(action.Params["path"])
	}
	if action.HostHeader == "" {
		action.HostHeader = stringValue(stringAny(action.Params["host_header"]), stringAny(action.Params["host"]))
	}
	if action.SNI == "" {
		action.SNI = stringAny(action.Params["sni"])
	}
	if action.Body == "" {
		action.Body = decodeEscapedText(stringAny(action.Params["body"]))
	}
	if action.Payload == "" {
		action.Payload = decodeEscapedText(stringAny(action.Params["payload"]))
	}
	if action.ReadBytes == 0 {
		action.ReadBytes = intAny(action.Params["read_bytes"])
	}
	if len(action.Headers) == 0 {
		action.Headers = stringMapAny(action.Params["headers"])
	}
	if !action.InsecureSkipVerify {
		action.InsecureSkipVerify = boolAny(action.Params["insecure_skip_verify"])
	}
}

// templateMatchesTarget 判断模板的 AppliesTo 条件是否匹配给定目标
func templateMatchesTarget(spec TemplateSpec, target TargetContext) bool {
	if spec.AppliesTo.IsZero() {
		return true
	}
	apply := spec.AppliesTo

	if protocol := normalizeProtocol(apply.Protocol); protocol != "" && protocol != normalizeProtocol(target.Protocol) {
		return false
	}
	if len(apply.Ports) > 0 {
		matched := false
		for _, port := range apply.Ports {
			if port == target.Port {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(apply.CurrentService) > 0 {
		if strings.TrimSpace(target.CurrentService) != "" {
			matched := false
			for _, item := range apply.CurrentService {
				if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target.CurrentService)) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if len(apply.Scheme) > 0 {
		matched := false
		for _, item := range apply.Scheme {
			if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target.Scheme)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(apply.SourceTool) > 0 {
		if strings.TrimSpace(target.Source) != "" {
			matched := false
			for _, item := range apply.SourceTool {
				if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target.Source)) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

// stringAny 将任意类型安全转为字符串
func stringAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case []byte:
		return strings.TrimSpace(string(typed))
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

// intAny 将任意类型安全转为 int
func intAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(typed))
		return n
	default:
		return 0
	}
}

// boolAny 将任意类型安全转为 bool
func boolAny(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

// stringMapAny 将任意类型安全转为 map[string]string
func stringMapAny(value any) map[string]string {
	switch typed := value.(type) {
	case map[string]string:
		return cloneStringMap(typed)
	case map[string]any:
		out := make(map[string]string, len(typed))
		for key, item := range typed {
			out[strings.TrimSpace(key)] = stringAny(item)
		}
		return out
	default:
		return nil
	}
}

// stringSliceAny 将任意类型安全转为 []string
func stringSliceAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := stringAny(item)
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
