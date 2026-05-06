package gping

import (
	uamservice "Going_Scan/internal/uam/service"
	"context"
	"fmt"
	"strings"
	"time"
)

// HistoryFilter 定义 gping 历史记录的查询筛选条件
type HistoryFilter struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	RunID    string `json:"run_id,omitempty"`
}

// HistoryResult 包含一次 gping 历史查询的完整结果
type HistoryResult struct {
	GeneratedAt  string                      `json:"generated_at"`
	Filter       HistoryFilter               `json:"filter"`
	Endpoint     *uamservice.EndpointAsset   `json:"endpoint,omitempty"`
	Runs         []uamservice.RunSummary     `json:"runs,omitempty"`
	Observations []uamservice.ObservationRow `json:"observations,omitempty"`
}

// BuildHistory 从 UAM 数据库中查询 gping 历史运行记录
func BuildHistory(ctx context.Context, dbPath string, filter HistoryFilter, limit int) (HistoryResult, error) {
	if strings.TrimSpace(dbPath) == "" {
		return HistoryResult{}, fmt.Errorf("--uam-db is required")
	}
	if strings.TrimSpace(filter.IP) == "" && strings.TrimSpace(filter.RunID) == "" {
		return HistoryResult{}, fmt.Errorf("--ip or --run-id is required for gping history")
	}
	if limit <= 0 {
		limit = 20
	}

	queryService, err := uamservice.OpenQueryService(dbPath)
	if err != nil {
		return HistoryResult{}, err
	}
	defer queryService.Close()

	if err := queryService.MustOpen(ctx); err != nil {
		return HistoryResult{}, err
	}

	queryFilter := uamservice.QueryFilter{
		IP:       strings.TrimSpace(filter.IP),
		Port:     filter.Port,
		Protocol: strings.ToLower(strings.TrimSpace(filter.Protocol)),
		Tool:     "gping",
		RunID:    strings.TrimSpace(filter.RunID),
	}

	observations, err := queryService.ListObservationsFiltered(ctx, queryFilter, limit)
	if err != nil {
		return HistoryResult{}, err
	}
	runs, err := queryService.ListRunsFiltered(ctx, queryFilter, minInt(limit, 20))
	if err != nil {
		return HistoryResult{}, err
	}

	var endpoint *uamservice.EndpointAsset
	if strings.TrimSpace(filter.IP) != "" && filter.Port > 0 {
		endpoints, err := queryService.ListEndpointsFiltered(ctx, uamservice.QueryFilter{
			IP:       strings.TrimSpace(filter.IP),
			Port:     filter.Port,
			Protocol: strings.ToLower(strings.TrimSpace(filter.Protocol)),
		}, 1)
		if err != nil {
			return HistoryResult{}, err
		}
		if len(endpoints) > 0 {
			endpoint = &endpoints[0]
		}
	}

	return HistoryResult{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Filter:       queryToHistoryFilter(queryFilter),
		Endpoint:     endpoint,
		Runs:         runs,
		Observations: observations,
	}, nil
}

// RenderHistory 将历史查询结果渲染为可读的文本输出
func RenderHistory(result HistoryResult, verbose bool) string {
	var b strings.Builder
	label := historyLabel(result.Filter)
	if len(result.Observations) == 0 && len(result.Runs) == 0 && result.Endpoint == nil {
		fmt.Fprintf(&b, "No gping history found for %s\n", label)
		return b.String()
	}

	fmt.Fprintf(&b, "gping history for %s\n", label)
	fmt.Fprintf(&b, "Generated at: %s\n\n", result.GeneratedAt)

	if result.Endpoint != nil {
		state := derefString(result.Endpoint.CurrentPortState)
		service := derefString(result.Endpoint.CurrentService)
		product := derefString(result.Endpoint.CurrentProduct)
		version := derefString(result.Endpoint.CurrentVersion)
		banner := derefString(result.Endpoint.CurrentBanner)
		fmt.Fprintf(&b, "Current Endpoint: state=%s service=%s verify=%s\n", dash(state), dash(service), dash(result.Endpoint.VerificationState))
		if product != "" || version != "" || banner != "" {
			parts := make([]string, 0, 3)
			if product != "" {
				parts = append(parts, "product="+product)
			}
			if version != "" {
				parts = append(parts, "version="+version)
			}
			if banner != "" {
				parts = append(parts, "banner="+banner)
			}
			fmt.Fprintf(&b, "Details: %s\n", strings.Join(parts, "  "))
		}
		b.WriteString("\n")
	}

	if len(result.Runs) > 0 {
		b.WriteString("Recent gping runs:\n")
		for _, run := range result.Runs {
			finished := "running"
			if run.FinishedAt != nil {
				finished = *run.FinishedAt
			}
			fmt.Fprintf(&b, "  %s  started=%s  finished=%s\n", run.RunID, run.StartedAt, finished)
		}
		b.WriteString("\n")
	}

	if len(result.Observations) > 0 {
		b.WriteString("Observations:\n")
		for index, item := range result.Observations {
			fmt.Fprintf(&b, "  %d. %s", index+1, item.ObservedAt)
			if item.RouteUsed != nil || item.RawMethod != nil || item.RawStatus != nil {
				fmt.Fprintf(&b, "  %s/%s -> %s",
					dash(derefString(item.RouteUsed)),
					dash(derefString(item.RawMethod)),
					dash(derefString(item.RawStatus)),
				)
			}
			if item.RunID != "" {
				fmt.Fprintf(&b, "  [run=%s]", item.RunID)
			}
			if item.Port != nil && item.Protocol != nil {
				fmt.Fprintf(&b, "  [%d/%s]", *item.Port, strings.ToLower(*item.Protocol))
			}
			b.WriteString("\n")
			if item.RequestSummary != nil && *item.RequestSummary != "" {
				fmt.Fprintf(&b, "     request: %s\n", *item.RequestSummary)
			}
			if item.ResponseSummary != nil && *item.ResponseSummary != "" {
				fmt.Fprintf(&b, "     response: %s\n", *item.ResponseSummary)
			}
			if item.ErrorText != nil && *item.ErrorText != "" {
				fmt.Fprintf(&b, "     error: %s\n", *item.ErrorText)
			}
			if item.RTTMs != nil {
				fmt.Fprintf(&b, "     rtt_ms: %.1f\n", *item.RTTMs)
			}
			if verbose && item.ExtraJSON != nil && *item.ExtraJSON != "" {
				fmt.Fprintf(&b, "     extra_json: %s\n", *item.ExtraJSON)
			}
		}
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

func historyLabel(filter HistoryFilter) string {
	parts := make([]string, 0, 3)
	if filter.IP != "" {
		parts = append(parts, filter.IP)
	}
	if filter.Port > 0 {
		protocol := stringValue(filter.Protocol, "tcp")
		parts = append(parts, fmt.Sprintf("%d/%s", filter.Port, strings.ToLower(protocol)))
	}
	if filter.RunID != "" {
		parts = append(parts, "run="+filter.RunID)
	}
	if len(parts) == 0 {
		return "gping selection"
	}
	return strings.Join(parts, " ")
}

func queryToHistoryFilter(filter uamservice.QueryFilter) HistoryFilter {
	return HistoryFilter{
		IP:       strings.TrimSpace(filter.IP),
		Port:     filter.Port,
		Protocol: strings.ToLower(strings.TrimSpace(filter.Protocol)),
		RunID:    strings.TrimSpace(filter.RunID),
	}
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return strings.TrimSpace(value)
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
