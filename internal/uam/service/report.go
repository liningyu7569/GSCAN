package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// HostReport 主机综合报告，聚合主机状态、端口资产、观测记录和Run历史
type HostReport struct {
	GeneratedAt  string           `json:"generated_at"`
	Filter       QueryFilter      `json:"filter"`
	Host         *HostAsset       `json:"host,omitempty"`
	Runs         []RunSummary     `json:"runs"`
	Endpoints    []EndpointAsset  `json:"endpoints"`
	Observations []ObservationRow `json:"observations"`
}

// BuildHostReport 构建指定IP的主机综合报告，聚合host/endpoints/observations/runs
func (q *QueryService) BuildHostReport(ctx context.Context, filter QueryFilter, limit int) (HostReport, error) {
	if strings.TrimSpace(filter.IP) == "" {
		return HostReport{}, fmt.Errorf("ip filter is required for host report")
	}
	if limit <= 0 {
		limit = 200
	}

	hosts, err := q.ListHostsFiltered(ctx, QueryFilter{
		IP:       filter.IP,
		Port:     filter.Port,
		Protocol: filter.Protocol,
		Tool:     filter.Tool,
		RunID:    filter.RunID,
	}, 1)
	if err != nil {
		return HostReport{}, err
	}

	endpoints, err := q.ListEndpointsFiltered(ctx, filter, limit)
	if err != nil {
		return HostReport{}, err
	}

	observations, err := q.ListObservationsFiltered(ctx, filter, limit*4)
	if err != nil {
		return HostReport{}, err
	}

	runs, err := q.ListRunsFiltered(ctx, filter, 20)
	if err != nil {
		return HostReport{}, err
	}

	report := HostReport{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Filter:       filter,
		Runs:         runs,
		Endpoints:    endpoints,
		Observations: observations,
	}
	if len(hosts) > 0 {
		report.Host = &hosts[0]
	}
	return report, nil
}

// RenderHostReport 将HostReport渲染为人类可读的文本格式
func RenderHostReport(report HostReport) string {
	var b strings.Builder
	ip := strings.TrimSpace(report.Filter.IP)
	if ip == "" && report.Host != nil {
		ip = report.Host.IP
	}

	if report.Host == nil && len(report.Endpoints) == 0 && len(report.Observations) == 0 {
		fmt.Fprintf(&b, "No UAM data found for %s\n", ip)
		return b.String()
	}

	fmt.Fprintf(&b, "UAM Report for %s\n", ip)
	fmt.Fprintf(&b, "Generated at: %s\n", report.GeneratedAt)
	fmt.Fprintf(&b, "Filter: ip=%s", ip)
	if report.Filter.Port > 0 {
		fmt.Fprintf(&b, " port=%d", report.Filter.Port)
	}
	if strings.TrimSpace(report.Filter.Protocol) != "" {
		fmt.Fprintf(&b, " protocol=%s", strings.ToLower(strings.TrimSpace(report.Filter.Protocol)))
	}
	if strings.TrimSpace(report.Filter.Tool) != "" {
		fmt.Fprintf(&b, " tool=%s", strings.TrimSpace(report.Filter.Tool))
	}
	if strings.TrimSpace(report.Filter.RunID) != "" {
		fmt.Fprintf(&b, " run=%s", strings.TrimSpace(report.Filter.RunID))
	}
	b.WriteString("\n\n")

	if report.Host != nil {
		reachability := "-"
		if report.Host.CurrentReachability != nil {
			reachability = *report.Host.CurrentReachability
		}
		confidence := "-"
		if report.Host.ReachabilityConfidence != nil {
			confidence = fmt.Sprintf("%d", *report.Host.ReachabilityConfidence)
		}
		source := "-"
		if report.Host.SourceTool != nil {
			source = *report.Host.SourceTool
		}
		lastSeen := "-"
		if report.Host.LastSeenAt != nil {
			lastSeen = *report.Host.LastSeenAt
		}
		fmt.Fprintf(&b, "Host Status: %s (confidence=%s, verification=%s, source=%s, last_seen=%s)\n\n",
			reachability, confidence, report.Host.VerificationState, source, lastSeen)
	}

	if len(report.Runs) > 0 {
		b.WriteString("Recent Runs:\n")
		for _, run := range report.Runs {
			finished := "running"
			if run.FinishedAt != nil {
				finished = *run.FinishedAt
			}
			fmt.Fprintf(&b, "  %s  [%s/%s]  started=%s  finished=%s\n",
				run.RunID, run.Tool, run.ModuleName, run.StartedAt, finished)
		}
		b.WriteString("\n")
	}

	if len(report.Endpoints) > 0 {
		b.WriteString("PORT      STATE         SERVICE        VERSION/INFO                    SOURCE   VERIFY\n")
		for _, endpoint := range report.Endpoints {
			portLabel := fmt.Sprintf("%d/%s", endpoint.Port, strings.ToLower(endpoint.Protocol))
			state := derefOr(endpoint.CurrentPortState, "-")
			service := derefOr(endpoint.CurrentService, "-")
			version := summarizeEndpoint(endpoint)
			source := derefOr(endpoint.SourceTool, "-")
			verify := endpoint.VerificationState
			fmt.Fprintf(&b, "%-9s %-13s %-14s %-30s %-8s %s\n", portLabel, state, service, version, source, verify)
		}
		b.WriteString("\n")
	}

	hostObservations, endpointObservations := groupObservations(report.Observations)

	if len(hostObservations) > 0 {
		b.WriteString("Host Facts:\n")
		for _, observation := range hostObservations {
			fmt.Fprintf(&b, "  %s  %s -> %s", observation.ObservedAt, derefOr(observation.RawMethod, "-"), derefOr(observation.RawStatus, "-"))
			if observation.RunID != "" {
				fmt.Fprintf(&b, "  [run=%s]", observation.RunID)
			}
			if observation.ResponseSummary != nil && *observation.ResponseSummary != "" {
				fmt.Fprintf(&b, "  %s", *observation.ResponseSummary)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	endpointKeys := make([]string, 0, len(endpointObservations))
	for key := range endpointObservations {
		endpointKeys = append(endpointKeys, key)
	}
	sort.Strings(endpointKeys)

	for _, key := range endpointKeys {
		fmt.Fprintf(&b, "%s Facts:\n", key)
		for _, observation := range endpointObservations[key] {
			fmt.Fprintf(&b, "  %s  %s -> %s", observation.ObservedAt, derefOr(observation.RawMethod, "-"), derefOr(observation.RawStatus, "-"))
			if observation.RunID != "" {
				fmt.Fprintf(&b, "  [run=%s]", observation.RunID)
			}
			if observation.RouteUsed != nil && *observation.RouteUsed != "" {
				fmt.Fprintf(&b, "  route=%s", *observation.RouteUsed)
			}
			if observation.ResponseSummary != nil && *observation.ResponseSummary != "" {
				fmt.Fprintf(&b, "  %s", *observation.ResponseSummary)
			}
			if observation.ErrorText != nil && *observation.ErrorText != "" {
				fmt.Fprintf(&b, "  error=%s", *observation.ErrorText)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

func summarizeEndpoint(endpoint EndpointAsset) string {
	parts := make([]string, 0, 3)
	if endpoint.CurrentProduct != nil && *endpoint.CurrentProduct != "" {
		parts = append(parts, *endpoint.CurrentProduct)
	}
	if endpoint.CurrentVersion != nil && *endpoint.CurrentVersion != "" {
		parts = append(parts, *endpoint.CurrentVersion)
	}
	if endpoint.CurrentInfo != nil && *endpoint.CurrentInfo != "" {
		parts = append(parts, "("+*endpoint.CurrentInfo+")")
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	if endpoint.CurrentBanner != nil && *endpoint.CurrentBanner != "" {
		return *endpoint.CurrentBanner
	}
	return "-"
}

func groupObservations(observations []ObservationRow) ([]ObservationRow, map[string][]ObservationRow) {
	hostFacts := make([]ObservationRow, 0)
	endpointFacts := make(map[string][]ObservationRow)

	for _, observation := range observations {
		if observation.Port == nil || observation.Protocol == nil {
			hostFacts = append(hostFacts, observation)
			continue
		}
		key := fmt.Sprintf("%d/%s", *observation.Port, strings.ToLower(*observation.Protocol))
		endpointFacts[key] = append(endpointFacts[key], observation)
	}

	return hostFacts, endpointFacts
}

func derefOr(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}
