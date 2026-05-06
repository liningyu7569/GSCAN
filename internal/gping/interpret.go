package gping

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// interpretEvidence 将路由证据解释为结构化执行报告，包含推断的 UAM 断言
func interpretEvidence(target TargetContext, action ActionUnit, evidence routeEvidence) ExecutionReport {
	report := ExecutionReport{
		IP:              target.IP,
		Protocol:        target.Protocol,
		Port:            target.Port,
		StepID:          action.ID,
		RouteUsed:       action.Route,
		ActionType:      actionTypeForMethod(action.Method),
		RawMethod:       action.Method,
		RawStatus:       evidence.RawStatus,
		RequestSummary:  evidence.RequestSummary,
		ResponseSummary: evidence.ResponseSummary,
		RTTMs:           evidence.RTTMs,
		ErrorText:       evidence.ErrorText,
		ExtraJSON:       marshalExtraJSON(evidence.Extra),
	}
	report.Claims = buildClaimsFromEvidence(target, action, evidence)
	return report
}

// actionTypeForMethod 将探测方法映射到 UAM 动作类型（reach/collect/handshake/request/probe）
func actionTypeForMethod(method string) string {
	switch normalizeMethod(method) {
	case "icmp-echo-raw":
		return domain.ActionReach
	case "banner-read", "ssh-banner", "smtp-banner", "ftp-banner":
		return domain.ActionCollect
	case "tls-handshake", "mysql-greeting", "mysql-capabilities", "mysql-starttls", "ssh-kexinit", "ssh-hostkey", "smtp-starttls", "ftp-auth-tls":
		return domain.ActionHandshake
	case "http-head", "http-get", "http-post", "dns-query", "ftp-feat", "smtp-ehlo", "redis-ping", "redis-info-server", "redis-info-replication":
		return domain.ActionRequest
	default:
		return domain.ActionProbe
	}
}

// buildClaimsFromEvidence 根据证据为每种方法生成对应的 UAM 断言（端口状态、服务名、版本等）
func buildClaimsFromEvidence(target TargetContext, action ActionUnit, evidence routeEvidence) []normalize.GPingClaimInput {
	method := normalizeMethod(action.Method)
	claims := make([]normalize.GPingClaimInput, 0, 10)
	if evidence.RawStatus == "skipped" {
		return claims
	}

	switch method {
	case "tcp-syn":
		claims = append(claims, networkPortStateClaims(evidence.RawStatus)...)
		if evidence.RawStatus == "open" || evidence.RawStatus == "closed" {
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 92, domain.AssertionObserved))
		}
	case "tcp-raw":
		flags := strings.ToLower(stringAny(evidence.Extra["flags"]))
		switch {
		case strings.Contains(flags, "syn") && strings.Contains(flags, "ack"):
			claims = append(claims, networkPortStateClaims("open")...)
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 90, domain.AssertionObserved))
		case strings.Contains(flags, "rst"):
			claims = append(claims, networkPortStateClaims("closed")...)
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 88, domain.AssertionObserved))
		case evidence.RawStatus == "icmp-unreachable":
			claims = append(claims, networkPortStateClaims("filtered")...)
		}
	case "icmp-echo-raw":
		switch evidence.RawStatus {
		case "reachable":
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 96, domain.AssertionObserved))
		case "timeout":
			claims = append(claims, hostReachabilityClaim(domain.HostUnreachable, 55, domain.AssertionInferred))
		}
	case "icmp-raw":
		if evidence.RawStatus != "timeout" && evidence.RawStatus != "error" {
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 82, domain.AssertionObserved))
		}
	case "tcp-connect":
		claims = append(claims, networkPortStateClaims(evidence.RawStatus)...)
		switch evidence.RawStatus {
		case "open", "closed":
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		}
	case "banner-read":
		switch evidence.RawStatus {
		case "banner", "open", "timeout":
			claims = append(claims, networkPortStateClaims("open")...)
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		case "closed":
			claims = append(claims, networkPortStateClaims(evidence.RawStatus)...)
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 88, domain.AssertionObserved))
		case "filtered":
			claims = append(claims, networkPortStateClaims(evidence.RawStatus)...)
		}
		if evidence.Banner != "" {
			claims = append(claims, endpointTextClaim("service", "banner", evidence.Banner, 88, domain.AssertionObserved))
		}
		if evidence.Product != "" {
			claims = append(claims, endpointTextClaim("service", "product", evidence.Product, 74, domain.AssertionObserved))
		}
		if evidence.Version != "" {
			claims = append(claims, endpointTextClaim("service", "version", evidence.Version, 68, domain.AssertionObserved))
		}
	case "tls-handshake":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		if target.Scheme == "https" || target.Port == 443 || strings.Contains(strings.ToLower(evidence.TLSALPN), "http") {
			claims = append(claims, endpointTextClaim("service", "name", "https", 82, domain.AssertionObserved))
		}
		if evidence.TLSSubject != "" {
			claims = append(claims, endpointTextClaim("tls", "subject", evidence.TLSSubject, 90, domain.AssertionObserved))
		}
		if evidence.TLSIssuer != "" {
			claims = append(claims, endpointTextClaim("tls", "issuer", evidence.TLSIssuer, 88, domain.AssertionObserved))
		}
		if len(evidence.TLSSANs) > 0 {
			if raw, err := json.Marshal(evidence.TLSSANs); err == nil {
				claims = append(claims, endpointJSONClaim("tls", "san", string(raw), 88, domain.AssertionObserved))
			}
		}
		if evidence.TLSALPN != "" {
			claims = append(claims, endpointTextClaim("tls", "alpn", evidence.TLSALPN, 84, domain.AssertionObserved))
		}
	case "http-head", "http-get", "http-post":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		serviceName := "http"
		if strings.EqualFold(target.Scheme, "https") {
			serviceName = "https"
		}
		claims = append(claims, endpointTextClaim("service", "name", serviceName, 86, domain.AssertionObserved))
		if evidence.Server != "" {
			claims = append(claims, endpointTextClaim("http", "server", evidence.Server, 88, domain.AssertionObserved))
			claims = append(claims, endpointTextClaim("service", "banner", evidence.Server, 86, domain.AssertionObserved))
		}
		if evidence.Product != "" {
			claims = append(claims, endpointTextClaim("service", "product", evidence.Product, 84, domain.AssertionObserved))
		}
		if evidence.Version != "" {
			claims = append(claims, endpointTextClaim("service", "version", evidence.Version, 78, domain.AssertionObserved))
		}
		if evidence.StatusCode > 0 {
			claims = append(claims, endpointTextClaim("http", "status_code", fmt.Sprintf("%d", evidence.StatusCode), 92, domain.AssertionObserved))
		}
		if evidence.Title != "" {
			claims = append(claims, endpointTextClaim("http", "title", evidence.Title, 84, domain.AssertionObserved))
		}
		if evidence.Location != "" {
			claims = append(claims, endpointTextClaim("http", "location", evidence.Location, 82, domain.AssertionObserved))
		}
	case "dns-query":
		claims = append(claims, endpointTextClaim("service", "name", "dns", 88, domain.AssertionObserved))
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 92, domain.AssertionObserved))
		if target.Port > 0 && strings.EqualFold(target.Protocol, "tcp") {
			claims = append(claims, networkPortStateClaims("open")...)
		}
		if rcode := stringAny(evidence.Fields["rcode"]); rcode != "" {
			claims = append(claims, endpointTextClaim("dns", "rcode", rcode, 86, domain.AssertionObserved))
		}
		if answerCount := stringAny(evidence.Fields["answer_count"]); answerCount != "" {
			claims = append(claims, endpointTextClaim("dns", "answer_count", answerCount, 84, domain.AssertionObserved))
		}
		if recursion := stringAny(evidence.Fields["recursion_available"]); recursion != "" {
			claims = append(claims, endpointTextClaim("dns", "recursion_available", recursion, 80, domain.AssertionObserved))
		}
		if role := stringAny(evidence.Fields["response_role"]); role != "" && role != "unknown" {
			claims = append(claims, endpointTextClaim("dns", "response_role", role, 72, domain.AssertionObserved))
		}
	case "ftp-banner", "ftp-feat", "ftp-auth-tls":
		if evidence.RawStatus != "error" || evidence.Banner != "" || stringAny(evidence.Fields["response_code"]) != "" {
			claims = append(claims, networkPortStateClaims("open")...)
			claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
			claims = append(claims, endpointTextClaim("service", "name", "ftp", 88, domain.AssertionObserved))
		}
		if evidence.Banner != "" {
			claims = append(claims, endpointTextClaim("service", "banner", evidence.Banner, 86, domain.AssertionObserved))
		}
		if responseCode := stringAny(evidence.Fields["response_code"]); responseCode != "" {
			claims = append(claims, endpointTextClaim("ftp", "response_code", responseCode, 84, domain.AssertionObserved))
		}
		if featOK := stringAny(evidence.Fields["feat_ok"]); featOK != "" {
			claims = append(claims, endpointTextClaim("ftp", "feat_ok", featOK, 82, domain.AssertionObserved))
		}
		if authTLSAdvertised := stringAny(evidence.Fields["auth_tls_advertised"]); authTLSAdvertised != "" {
			claims = append(claims, endpointTextClaim("ftp", "auth_tls_advertised", authTLSAdvertised, 82, domain.AssertionObserved))
		}
		if authTLSOK := stringAny(evidence.Fields["auth_tls_ok"]); authTLSOK != "" {
			claims = append(claims, endpointTextClaim("ftp", "auth_tls_ok", authTLSOK, 82, domain.AssertionObserved))
		}
		if capabilities, ok := evidence.Fields["features"]; ok {
			if raw, err := json.Marshal(capabilities); err == nil {
				claims = append(claims, endpointJSONClaim("ftp", "features", string(raw), 80, domain.AssertionObserved))
			}
		}
		if product := stringAny(evidence.Fields["product"]); product != "" {
			claims = append(claims, endpointTextClaim("service", "product", product, 70, domain.AssertionObserved))
		}
		if version := stringAny(evidence.Fields["version"]); version != "" {
			claims = append(claims, endpointTextClaim("service", "version", version, 68, domain.AssertionObserved))
		}
		if subject := stringAny(evidence.Fields["tls_subject"]); subject != "" {
			claims = append(claims, endpointTextClaim("tls", "subject", subject, 88, domain.AssertionObserved))
		}
		if issuer := stringAny(evidence.Fields["tls_issuer"]); issuer != "" {
			claims = append(claims, endpointTextClaim("tls", "issuer", issuer, 86, domain.AssertionObserved))
		}
		if sans, ok := evidence.Fields["tls_san"]; ok {
			if raw, err := json.Marshal(sans); err == nil {
				claims = append(claims, endpointJSONClaim("tls", "san", string(raw), 86, domain.AssertionObserved))
			}
		}
	case "smtp-banner", "smtp-ehlo", "smtp-starttls":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		claims = append(claims, endpointTextClaim("service", "name", "smtp", 88, domain.AssertionObserved))
		if evidence.Banner != "" {
			claims = append(claims, endpointTextClaim("service", "banner", evidence.Banner, 86, domain.AssertionObserved))
		}
		if responseCode := stringAny(evidence.Fields["response_code"]); responseCode != "" {
			claims = append(claims, endpointTextClaim("smtp", "response_code", responseCode, 84, domain.AssertionObserved))
		}
		if ehloOK := stringAny(evidence.Fields["ehlo_ok"]); ehloOK != "" {
			claims = append(claims, endpointTextClaim("smtp", "ehlo_ok", ehloOK, 82, domain.AssertionObserved))
		}
		if starttlsAdvertised := stringAny(evidence.Fields["starttls_advertised"]); starttlsAdvertised != "" {
			claims = append(claims, endpointTextClaim("smtp", "starttls_advertised", starttlsAdvertised, 82, domain.AssertionObserved))
		}
		if starttlsOK := stringAny(evidence.Fields["starttls_ok"]); starttlsOK != "" {
			claims = append(claims, endpointTextClaim("smtp", "starttls_ok", starttlsOK, 82, domain.AssertionObserved))
		}
		if capabilities, ok := evidence.Fields["capabilities"]; ok {
			if raw, err := json.Marshal(capabilities); err == nil {
				claims = append(claims, endpointJSONClaim("smtp", "capabilities", string(raw), 80, domain.AssertionObserved))
			}
		}
		if product := stringAny(evidence.Fields["product"]); product != "" {
			claims = append(claims, endpointTextClaim("service", "product", product, 70, domain.AssertionObserved))
		}
		if version := stringAny(evidence.Fields["version"]); version != "" {
			claims = append(claims, endpointTextClaim("service", "version", version, 68, domain.AssertionObserved))
		}
		if subject := stringAny(evidence.Fields["tls_subject"]); subject != "" {
			claims = append(claims, endpointTextClaim("tls", "subject", subject, 88, domain.AssertionObserved))
		}
		if issuer := stringAny(evidence.Fields["tls_issuer"]); issuer != "" {
			claims = append(claims, endpointTextClaim("tls", "issuer", issuer, 86, domain.AssertionObserved))
		}
		if sans, ok := evidence.Fields["tls_san"]; ok {
			if raw, err := json.Marshal(sans); err == nil {
				claims = append(claims, endpointJSONClaim("tls", "san", string(raw), 86, domain.AssertionObserved))
			}
		}
	case "redis-ping", "redis-info-server", "redis-info-replication":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		if pingOK := stringAny(evidence.Fields["ping_ok"]); pingOK == "true" || stringAny(evidence.Fields["auth_required"]) == "true" || evidence.RawStatus == "success" {
			claims = append(claims, endpointTextClaim("service", "name", "redis", 88, domain.AssertionObserved))
		}
		if pingOK := stringAny(evidence.Fields["ping_ok"]); pingOK != "" {
			claims = append(claims, endpointTextClaim("redis", "ping_ok", pingOK, 84, domain.AssertionObserved))
		}
		if authRequired := stringAny(evidence.Fields["auth_required"]); authRequired != "" {
			claims = append(claims, endpointTextClaim("redis", "auth_required", authRequired, 84, domain.AssertionObserved))
		}
		if version := stringAny(evidence.Fields["redis_version"]); version != "" {
			claims = append(claims, endpointTextClaim("service", "version", version, 82, domain.AssertionObserved))
		}
		if mode := stringAny(evidence.Fields["redis_mode"]); mode != "" {
			claims = append(claims, endpointTextClaim("redis", "mode", mode, 80, domain.AssertionObserved))
		}
		if role := stringAny(evidence.Fields["role"]); role != "" {
			claims = append(claims, endpointTextClaim("redis", "role", role, 80, domain.AssertionObserved))
		}
		if infoAccessible := stringAny(evidence.Fields["info_accessible"]); infoAccessible != "" {
			claims = append(claims, endpointTextClaim("redis", "info_accessible", infoAccessible, 76, domain.AssertionObserved))
		}
	case "ssh-banner", "ssh-kexinit", "ssh-hostkey":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		claims = append(claims, endpointTextClaim("service", "name", "ssh", 88, domain.AssertionObserved))
		if evidence.Banner != "" {
			claims = append(claims, endpointTextClaim("service", "banner", evidence.Banner, 86, domain.AssertionObserved))
		}
		if protocolVersion := stringAny(evidence.Fields["protocol_version"]); protocolVersion != "" {
			claims = append(claims, endpointTextClaim("ssh", "protocol_version", protocolVersion, 84, domain.AssertionObserved))
		}
		if softwareVersion := stringAny(evidence.Fields["software_version"]); softwareVersion != "" {
			claims = append(claims, endpointTextClaim("ssh", "software_version", softwareVersion, 84, domain.AssertionObserved))
		}
		if product := stringAny(evidence.Fields["product"]); product != "" {
			claims = append(claims, endpointTextClaim("service", "product", product, 74, domain.AssertionObserved))
		}
		if version := stringAny(evidence.Fields["version"]); version != "" {
			claims = append(claims, endpointTextClaim("service", "version", version, 74, domain.AssertionObserved))
		}
		if kexAlgorithms, ok := evidence.Fields["kex_algorithms"]; ok {
			if raw, err := json.Marshal(kexAlgorithms); err == nil {
				claims = append(claims, endpointJSONClaim("ssh", "kex_algorithms", string(raw), 82, domain.AssertionObserved))
			}
		}
		if hostKeyAlgorithms, ok := evidence.Fields["hostkey_algorithms"]; ok {
			if raw, err := json.Marshal(hostKeyAlgorithms); err == nil {
				claims = append(claims, endpointJSONClaim("ssh", "hostkey_algorithms", string(raw), 82, domain.AssertionObserved))
			}
		}
		if hostKeyType := stringAny(evidence.Fields["hostkey_type"]); hostKeyType != "" {
			claims = append(claims, endpointTextClaim("ssh", "hostkey_type", hostKeyType, 86, domain.AssertionObserved))
		}
		if fingerprint := stringAny(evidence.Fields["hostkey_fingerprint"]); fingerprint != "" {
			claims = append(claims, endpointTextClaim("ssh", "hostkey_fingerprint", fingerprint, 90, domain.AssertionObserved))
		}
	case "mysql-greeting", "mysql-capabilities", "mysql-starttls":
		claims = append(claims, networkPortStateClaims("open")...)
		claims = append(claims, hostReachabilityClaim(domain.HostReachable, 94, domain.AssertionObserved))
		claims = append(claims, endpointTextClaim("service", "name", "mysql", 88, domain.AssertionObserved))
		serverVersion := stringValue(stringAny(evidence.Fields["server_version"]), evidence.Version)
		if serverVersion != "" {
			claims = append(claims, endpointTextClaim("service", "banner", serverVersion, 84, domain.AssertionObserved))
			claims = append(claims, endpointTextClaim("service", "version", serverVersion, 84, domain.AssertionObserved))
		}
		if protocolVersion := stringAny(evidence.Fields["protocol_version"]); protocolVersion != "" {
			claims = append(claims, endpointTextClaim("mysql", "protocol_version", protocolVersion, 84, domain.AssertionObserved))
		}
		if authPlugin := stringAny(evidence.Fields["auth_plugin"]); authPlugin != "" {
			claims = append(claims, endpointTextClaim("mysql", "auth_plugin", authPlugin, 82, domain.AssertionObserved))
		}
		if sslSupported := stringAny(evidence.Fields["ssl_supported"]); sslSupported != "" {
			claims = append(claims, endpointTextClaim("mysql", "ssl_supported", sslSupported, 80, domain.AssertionObserved))
		}
		if sslOK := stringAny(evidence.Fields["ssl_handshake_ok"]); sslOK != "" {
			claims = append(claims, endpointTextClaim("mysql", "ssl_handshake_ok", sslOK, 80, domain.AssertionObserved))
		}
		if product := stringAny(evidence.Fields["product"]); product != "" {
			claims = append(claims, endpointTextClaim("service", "product", product, 72, domain.AssertionObserved))
		}
		if subject := stringAny(evidence.Fields["tls_subject"]); subject != "" {
			claims = append(claims, endpointTextClaim("tls", "subject", subject, 88, domain.AssertionObserved))
		}
		if issuer := stringAny(evidence.Fields["tls_issuer"]); issuer != "" {
			claims = append(claims, endpointTextClaim("tls", "issuer", issuer, 86, domain.AssertionObserved))
		}
		if sans, ok := evidence.Fields["tls_san"]; ok {
			if raw, err := json.Marshal(sans); err == nil {
				claims = append(claims, endpointJSONClaim("tls", "san", string(raw), 86, domain.AssertionObserved))
			}
		}
	}

	return claims
}

func networkPortStateClaims(state string) []normalize.GPingClaimInput {
	mode := domain.AssertionObserved
	confidence := 96
	switch state {
	case "filtered", "timeout":
		state = domain.PortStateFiltered
		mode = domain.AssertionInferred
		confidence = 60
	case "open":
		state = domain.PortStateOpen
	case "closed":
		state = domain.PortStateClosed
	default:
		return nil
	}
	return []normalize.GPingClaimInput{
		endpointTextClaim("network", "port_state", state, confidence, mode),
	}
}

func endpointTextClaim(namespace string, name string, value string, confidence int, mode string) normalize.GPingClaimInput {
	return normalize.GPingClaimInput{
		SubjectType:   domain.SubjectEndpoint,
		Namespace:     namespace,
		Name:          name,
		ValueText:     value,
		Confidence:    confidence,
		AssertionMode: mode,
	}
}

func endpointJSONClaim(namespace string, name string, value string, confidence int, mode string) normalize.GPingClaimInput {
	return normalize.GPingClaimInput{
		SubjectType:   domain.SubjectEndpoint,
		Namespace:     namespace,
		Name:          name,
		ValueJSON:     value,
		Confidence:    confidence,
		AssertionMode: mode,
	}
}

func hostReachabilityClaim(value string, confidence int, mode string) normalize.GPingClaimInput {
	return normalize.GPingClaimInput{
		SubjectType:   domain.SubjectHost,
		Namespace:     "network",
		Name:          "reachability",
		ValueText:     value,
		Confidence:    confidence,
		AssertionMode: mode,
	}
}

func summarizeHTTPStatus(statusCode int) string {
	if statusCode == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
}
