package l7

import "strings"

// Fingerprint 是 L7 阶段产出的结构化服务指纹。
// 这层保持机器可读，方便后续画像聚合与深扫调度使用。
type Fingerprint struct {
	Service  string
	Product  string
	Version  string
	Info     string
	Hostname string
	OS       string
	Device   string
	CPEs     []string
	Banner   string
}

func buildFingerprintFromRule(rule MatchRule, groups [][]byte, raw []byte) Fingerprint {
	fp := Fingerprint{
		Service:  rule.Service,
		Product:  expandTemplate(rule.Product, groups),
		Version:  expandTemplate(rule.Version, groups),
		Info:     expandTemplate(rule.Info, groups),
		Hostname: expandTemplate(rule.Hostname, groups),
		OS:       expandTemplate(rule.OS, groups),
		Device:   expandTemplate(rule.Device, groups),
	}

	if len(rule.CPEs) > 0 {
		fp.CPEs = make([]string, 0, len(rule.CPEs))
		for _, cpe := range rule.CPEs {
			expanded := expandTemplate(cpe, groups)
			if expanded != "" {
				fp.CPEs = append(fp.CPEs, expanded)
			}
		}
	}

	fp.Banner = formatFingerprintBanner(fp, raw)
	return fp
}

func formatFingerprintBanner(fp Fingerprint, raw []byte) string {
	var parts []string
	if fp.Product != "" {
		parts = append(parts, fp.Product)
	}
	if fp.Version != "" {
		parts = append(parts, fp.Version)
	}
	if fp.Info != "" {
		parts = append(parts, "("+fp.Info+")")
	}

	banner := strings.Join(parts, " ")
	if banner != "" {
		return banner
	}
	if len(raw) > 0 && !isBinaryProtocol(fp.Service) {
		return extractSafeBanner(raw)
	}
	return ""
}
