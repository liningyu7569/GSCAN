package normalize

import (
	"Going_Scan/internal/uam/domain"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GSResult GS的L4/L7服务探测结果，包含端口状态、服务识别等全部信息
type GSResult struct {
	IP       string
	Port     int
	Protocol string
	Method   string
	State    string
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

// GSDiscovery GS的主机发现结果，仅记录主机级可达性
type GSDiscovery struct {
	IP       string
	Method   string
	Status   string
	Protocol string
}

// ObservationFromGS 将GS扫描结果转换为Observation对象（L4端口扫描+L7服务识别）
func ObservationFromGS(runID string, hostID string, endpointID string, observationID string, observedAt time.Time, result GSResult) (domain.Observation, error) {
	extraJSON, err := marshalJSON(map[string]any{
		"protocol": result.Protocol,
		"service":  result.Service,
		"product":  result.Product,
		"version":  result.Version,
		"info":     result.Info,
		"hostname": result.Hostname,
		"os":       result.OS,
		"device":   result.Device,
		"cpes":     result.CPEs,
		"banner":   result.Banner,
	})
	if err != nil {
		return domain.Observation{}, err
	}

	responseSummary := strings.TrimSpace(strings.Join([]string{
		summaryPart("service", result.Service),
		summaryPart("product", result.Product),
		summaryPart("banner", result.Banner),
	}, " "))

	return domain.Observation{
		ObservationID:   observationID,
		RunID:           runID,
		Tool:            domain.ToolGS,
		ModuleName:      domain.ModuleNameGS,
		HostID:          hostID,
		EndpointID:      optionalString(endpointID),
		ActionType:      domain.ActionScan,
		RawMethod:       result.Method,
		RawStatus:       result.State,
		ResponseSummary: strings.TrimSpace(responseSummary),
		ObservedAt:      observedAt.UTC(),
		ExtraJSON:       extraJSON,
	}, nil
}

// ObservationFromGSDiscovery 将GS主机发现结果转换为Observation（纯主机级可达性探测）
func ObservationFromGSDiscovery(runID string, hostID string, observationID string, observedAt time.Time, discovery GSDiscovery) (domain.Observation, error) {
	extraJSON, err := marshalJSON(map[string]any{
		"protocol": discovery.Protocol,
	})
	if err != nil {
		return domain.Observation{}, err
	}

	return domain.Observation{
		ObservationID: observationID,
		RunID:         runID,
		Tool:          domain.ToolGS,
		ModuleName:    domain.ModuleNameGS,
		HostID:        hostID,
		ActionType:    domain.ActionScan,
		RawMethod:     discovery.Method,
		RawStatus:     discovery.Status,
		ObservedAt:    observedAt.UTC(),
		ExtraJSON:     extraJSON,
	}, nil
}

// ClaimsFromGS 从GS结果中提取完整Claim列表（包括可达性、端口状态和服务识别）
func ClaimsFromGS(observation domain.Observation, hostID string, endpointID string, now time.Time, result GSResult, nextClaimID func() string) []domain.Claim {
	claims := make([]domain.Claim, 0, 12)

	if reachability, mode, confidence, ok := normalizeReachability(result); ok {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectHost, hostID, "network", "reachability", reachability, confidence, mode, now))
	}

	if portState, mode, confidence, ok := normalizePortState(result); ok {
		claims = append(claims,
			newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "network", "port_state", portState, confidence, mode, now),
			newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "network", "discovery_method", result.Method, 100, domain.AssertionObserved, now),
		)
	}

	claims = append(claims, ServiceClaimsFromGS(observation, endpointID, now, result, nextClaimID)...)

	return claims
}

// ServiceClaimsFromGS 仅提取GS结果中的服务识别Claim（service/product/version等），不含可达性
func ServiceClaimsFromGS(observation domain.Observation, endpointID string, now time.Time, result GSResult, nextClaimID func() string) []domain.Claim {
	if endpointID == "" {
		return nil
	}

	claims := make([]domain.Claim, 0, 9)
	if result.Service != "" && result.Service != "unknown" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "name", result.Service, 82, domain.AssertionInferred, now))
	}
	if result.Product != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "product", result.Product, 78, domain.AssertionInferred, now))
	}
	if result.Version != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "version", result.Version, 76, domain.AssertionInferred, now))
	}
	if result.Info != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "info", result.Info, 74, domain.AssertionInferred, now))
	}
	if result.Hostname != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "hostname", result.Hostname, 72, domain.AssertionInferred, now))
	}
	if result.OS != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "os", result.OS, 72, domain.AssertionInferred, now))
	}
	if result.Device != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "device", result.Device, 72, domain.AssertionInferred, now))
	}
	if result.Banner != "" {
		claims = append(claims, newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "banner", result.Banner, 88, domain.AssertionObserved, now))
	}
	if len(result.CPEs) > 0 {
		rawJSON, err := marshalJSON(result.CPEs)
		if err == nil {
			claims = append(claims, newJSONClaim(nextClaimID(), observation.ObservationID, domain.SubjectEndpoint, endpointID, "service", "cpes", rawJSON, 78, domain.AssertionInferred, now))
		}
	}
	return claims
}

// ClaimsFromGSDiscovery 从GS主机发现结果中提取Claim（仅可达性声明）
func ClaimsFromGSDiscovery(observation domain.Observation, hostID string, now time.Time, discovery GSDiscovery, nextClaimID func() string) []domain.Claim {
	return []domain.Claim{
		newTextClaim(nextClaimID(), observation.ObservationID, domain.SubjectHost, hostID, "network", "reachability", domain.HostReachable, 96, domain.AssertionObserved, now),
	}
}

func normalizeReachability(result GSResult) (string, string, int, bool) {
	switch result.State {
	case "open", "closed", "unfiltered":
		return domain.HostReachable, domain.AssertionObserved, 92, true
	default:
		return "", "", 0, false
	}
}

func normalizePortState(result GSResult) (string, string, int, bool) {
	switch result.Method {
	case "tcp-syn":
		switch result.State {
		case "open", "closed":
			return result.State, domain.AssertionObserved, 96, true
		case "filtered":
			return domain.PortStateFiltered, domain.AssertionInferred, 60, true
		}
	case "udp":
		switch result.State {
		case "open", "closed":
			return result.State, domain.AssertionObserved, 90, true
		case "filtered":
			return domain.PortStateFiltered, domain.AssertionInferred, 58, true
		}
	case "tcp-ack":
		switch result.State {
		case "unfiltered":
			return domain.PortStateUnfiltered, domain.AssertionObserved, 84, true
		case "filtered":
			return domain.PortStateFiltered, domain.AssertionInferred, 60, true
		}
	case "tcp-window":
		switch result.State {
		case "open":
			return domain.PortStateLikelyOpen, domain.AssertionInferred, 72, true
		case "closed":
			return domain.PortStateClosed, domain.AssertionObserved, 88, true
		case "filtered":
			return domain.PortStateFiltered, domain.AssertionInferred, 60, true
		}
	}
	return "", "", 0, false
}

// newTextClaim 创建一个文本值类型的Claim
func newTextClaim(claimID string, observationID string, subjectType string, subjectID string, namespace string, name string, value string, confidence int, mode string, claimedAt time.Time) domain.Claim {
	return domain.Claim{
		ClaimID:       claimID,
		ObservationID: observationID,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		Namespace:     namespace,
		Name:          name,
		ValueText:     optionalString(value),
		Confidence:    confidence,
		AssertionMode: mode,
		ClaimedAt:     claimedAt.UTC(),
	}
}

// newJSONClaim 创建一个JSON值类型的Claim
func newJSONClaim(claimID string, observationID string, subjectType string, subjectID string, namespace string, name string, valueJSON string, confidence int, mode string, claimedAt time.Time) domain.Claim {
	return domain.Claim{
		ClaimID:       claimID,
		ObservationID: observationID,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		Namespace:     namespace,
		Name:          name,
		ValueJSON:     optionalString(valueJSON),
		Confidence:    confidence,
		AssertionMode: mode,
		ClaimedAt:     claimedAt.UTC(),
	}
}

func marshalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(raw), nil
}

func summaryPart(key string, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", key, value)
}

func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	value := v
	return &value
}
