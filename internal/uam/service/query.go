package service

import (
	sqlitestore "Going_Scan/internal/uam/store/sqlite"
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// QueryService UAM只读查询服务，封装常用资产、观测查询接口
type QueryService struct {
	store *sqlitestore.Store
}

// QueryFilter 查询过滤器，支持按IP/端口/协议/工具/RunID筛选
type QueryFilter struct {
	IP       string
	Port     int
	Protocol string
	Tool     string
	RunID    string
}

// RunSummary 运行记录摘要
type RunSummary struct {
	RunID       string  `json:"run_id"`
	Tool        string  `json:"tool"`
	ModuleName  string  `json:"module_name"`
	Commandline string  `json:"commandline,omitempty"`
	StartedAt   string  `json:"started_at"`
	FinishedAt  *string `json:"finished_at,omitempty"`
	ServiceScan bool    `json:"service_scan"`
}

// HostAsset 主机资产视图
type HostAsset struct {
	HostID                 string  `json:"host_id"`
	IP                     string  `json:"ip"`
	CurrentReachability    *string `json:"current_reachability,omitempty"`
	ReachabilityConfidence *int    `json:"reachability_confidence,omitempty"`
	VerificationState      string  `json:"verification_state"`
	LastSeenAt             *string `json:"last_seen_at,omitempty"`
	SourceTool             *string `json:"source_tool,omitempty"`
}

// EndpointAsset 端点资产视图
type EndpointAsset struct {
	EndpointID          string  `json:"endpoint_id"`
	IP                  string  `json:"ip"`
	Protocol            string  `json:"protocol"`
	Port                int     `json:"port"`
	CurrentPortState    *string `json:"current_port_state,omitempty"`
	PortStateConfidence *int    `json:"port_state_confidence,omitempty"`
	CurrentService      *string `json:"current_service,omitempty"`
	CurrentProduct      *string `json:"current_product,omitempty"`
	CurrentVersion      *string `json:"current_version,omitempty"`
	CurrentInfo         *string `json:"current_info,omitempty"`
	CurrentHostname     *string `json:"current_hostname,omitempty"`
	CurrentOS           *string `json:"current_os,omitempty"`
	CurrentDevice       *string `json:"current_device,omitempty"`
	CurrentBanner       *string `json:"current_banner,omitempty"`
	CurrentCPEsJSON     *string `json:"current_cpes_json,omitempty"`
	VerificationState   string  `json:"verification_state"`
	LastSeenAt          *string `json:"last_seen_at,omitempty"`
	SourceTool          *string `json:"source_tool,omitempty"`
}

// ObservationRow 观测记录行视图
type ObservationRow struct {
	ObservationID   string   `json:"observation_id"`
	RunID           string   `json:"run_id"`
	Tool            string   `json:"tool"`
	ModuleName      string   `json:"module_name"`
	IP              string   `json:"ip"`
	Protocol        *string  `json:"protocol,omitempty"`
	Port            *int     `json:"port,omitempty"`
	RouteUsed       *string  `json:"route_used,omitempty"`
	ActionType      string   `json:"action_type"`
	RawMethod       *string  `json:"raw_method,omitempty"`
	RawStatus       *string  `json:"raw_status,omitempty"`
	RequestSummary  *string  `json:"request_summary,omitempty"`
	ResponseSummary *string  `json:"response_summary,omitempty"`
	RTTMs           *float64 `json:"rtt_ms,omitempty"`
	ErrorText       *string  `json:"error_text,omitempty"`
	ExtraJSON       *string  `json:"extra_json,omitempty"`
	ObservedAt      string   `json:"observed_at"`
}

// OpenQueryService 打开已有UAM数据库，返回查询服务
func OpenQueryService(dbPath string) (*QueryService, error) {
	store, err := sqlitestore.OpenExisting(dbPath)
	if err != nil {
		return nil, err
	}
	return &QueryService{store: store}, nil
}

// Close 关闭查询服务的数据库连接
func (q *QueryService) Close() error {
	if q == nil || q.store == nil {
		return nil
	}
	return q.store.Close()
}

// MustOpen 验证数据库连接可用（Ping）
func (q *QueryService) MustOpen(ctx context.Context) error {
	if q == nil || q.store == nil {
		return fmt.Errorf("query service not initialized")
	}
	return q.store.DB().PingContext(ctx)
}

// ListRuns 列出最近的Run记录
func (q *QueryService) ListRuns(ctx context.Context, limit int) ([]RunSummary, error) {
	return q.ListRunsFiltered(ctx, QueryFilter{}, limit)
}

// ListRunsFiltered 按条件筛选并列出Run记录
func (q *QueryService) ListRunsFiltered(ctx context.Context, filter QueryFilter, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 20
	}

	query := strings.Builder{}
	query.WriteString(`
SELECT DISTINCT r.run_id, r.tool, r.module_name, r.commandline, r.started_at, r.finished_at, r.service_scan
FROM runs r
LEFT JOIN observations o ON o.run_id = r.run_id
LEFT JOIN hosts h ON h.host_id = o.host_id
LEFT JOIN endpoints e ON e.endpoint_id = o.endpoint_id`)

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)

	if ip := strings.TrimSpace(filter.IP); ip != "" {
		conditions = append(conditions, "h.ip = ?")
		args = append(args, ip)
	}
	if filter.Port > 0 {
		conditions = append(conditions, "e.port = ?")
		args = append(args, filter.Port)
	}
	if protocol := strings.ToLower(strings.TrimSpace(filter.Protocol)); protocol != "" {
		conditions = append(conditions, "e.protocol = ?")
		args = append(args, protocol)
	}
	if tool := strings.TrimSpace(filter.Tool); tool != "" {
		conditions = append(conditions, "r.tool = ?")
		args = append(args, tool)
	}
	if runID := strings.TrimSpace(filter.RunID); runID != "" {
		conditions = append(conditions, "r.run_id = ?")
		args = append(args, runID)
	}

	appendConditions(&query, conditions)
	query.WriteString("\nORDER BY r.started_at DESC\nLIMIT ?")
	args = append(args, limit)

	rows, err := q.store.DB().QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []RunSummary
	for rows.Next() {
		var (
			item       RunSummary
			command    sql.NullString
			finishedAt sql.NullString
			serviceInt int
		)
		if err := rows.Scan(&item.RunID, &item.Tool, &item.ModuleName, &command, &item.StartedAt, &finishedAt, &serviceInt); err != nil {
			return nil, err
		}
		if command.Valid {
			item.Commandline = command.String
		}
		if finishedAt.Valid {
			item.FinishedAt = &finishedAt.String
		}
		item.ServiceScan = serviceInt == 1
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListHosts 列出所有主机资产
func (q *QueryService) ListHosts(ctx context.Context, limit int) ([]HostAsset, error) {
	return q.ListHostsFiltered(ctx, QueryFilter{}, limit)
}

// ListHostsFiltered 按条件筛选并列出主机资产
func (q *QueryService) ListHostsFiltered(ctx context.Context, filter QueryFilter, limit int) ([]HostAsset, error) {
	if limit <= 0 {
		limit = 100
	}

	query := strings.Builder{}
	query.WriteString(`
SELECT DISTINCT
  v.host_id, v.ip, v.current_reachability, v.reachability_confidence,
  v.verification_state, v.last_seen_at, v.source_tool
FROM v_host_assets v
LEFT JOIN endpoints e ON e.host_id = v.host_id
LEFT JOIN observations o ON o.host_id = v.host_id`)

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)
	if ip := strings.TrimSpace(filter.IP); ip != "" {
		conditions = append(conditions, "v.ip = ?")
		args = append(args, ip)
	}
	if filter.Port > 0 {
		conditions = append(conditions, "e.port = ?")
		args = append(args, filter.Port)
	}
	if protocol := strings.ToLower(strings.TrimSpace(filter.Protocol)); protocol != "" {
		conditions = append(conditions, "e.protocol = ?")
		args = append(args, protocol)
	}
	if tool := strings.TrimSpace(filter.Tool); tool != "" {
		conditions = append(conditions, "o.tool = ?")
		args = append(args, tool)
	}
	if runID := strings.TrimSpace(filter.RunID); runID != "" {
		conditions = append(conditions, "o.run_id = ?")
		args = append(args, runID)
	}

	appendConditions(&query, conditions)
	query.WriteString("\nORDER BY v.ip\nLIMIT ?")
	args = append(args, limit)

	rows, err := q.store.DB().QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []HostAsset
	for rows.Next() {
		var (
			item       HostAsset
			reach      sql.NullString
			confidence sql.NullInt64
			verify     sql.NullString
			lastSeen   sql.NullString
			sourceTool sql.NullString
		)
		if err := rows.Scan(&item.HostID, &item.IP, &reach, &confidence, &verify, &lastSeen, &sourceTool); err != nil {
			return nil, err
		}
		item.CurrentReachability = nullStringPtr(reach)
		item.ReachabilityConfidence = nullIntPtr(confidence)
		item.VerificationState = nullStringDefault(verify, "none")
		item.LastSeenAt = nullStringPtr(lastSeen)
		item.SourceTool = nullStringPtr(sourceTool)
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListEndpoints 列出所有端点资产
func (q *QueryService) ListEndpoints(ctx context.Context, limit int) ([]EndpointAsset, error) {
	return q.ListEndpointsFiltered(ctx, QueryFilter{}, limit)
}

// ListEndpointsFiltered 按条件筛选并列出端点资产
func (q *QueryService) ListEndpointsFiltered(ctx context.Context, filter QueryFilter, limit int) ([]EndpointAsset, error) {
	if limit <= 0 {
		limit = 100
	}

	query := strings.Builder{}
	query.WriteString(`
SELECT DISTINCT
  v.endpoint_id, v.ip, v.protocol, v.port, v.current_port_state, v.port_state_confidence,
  v.current_service, v.current_product, v.current_version, v.current_info,
  v.current_hostname, v.current_os, v.current_device, v.current_banner,
  v.current_cpes_json, v.verification_state, v.last_seen_at, v.source_tool
FROM v_endpoint_assets v
LEFT JOIN observations o ON o.endpoint_id = v.endpoint_id`)

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)
	if ip := strings.TrimSpace(filter.IP); ip != "" {
		conditions = append(conditions, "v.ip = ?")
		args = append(args, ip)
	}
	if filter.Port > 0 {
		conditions = append(conditions, "v.port = ?")
		args = append(args, filter.Port)
	}
	if protocol := strings.ToLower(strings.TrimSpace(filter.Protocol)); protocol != "" {
		conditions = append(conditions, "v.protocol = ?")
		args = append(args, protocol)
	}
	if tool := strings.TrimSpace(filter.Tool); tool != "" {
		conditions = append(conditions, "o.tool = ?")
		args = append(args, tool)
	}
	if runID := strings.TrimSpace(filter.RunID); runID != "" {
		conditions = append(conditions, "o.run_id = ?")
		args = append(args, runID)
	}

	appendConditions(&query, conditions)
	query.WriteString("\nORDER BY v.ip, v.port, v.protocol\nLIMIT ?")
	args = append(args, limit)

	rows, err := q.store.DB().QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []EndpointAsset
	for rows.Next() {
		var (
			item       EndpointAsset
			portState  sql.NullString
			confidence sql.NullInt64
			service    sql.NullString
			product    sql.NullString
			version    sql.NullString
			info       sql.NullString
			hostname   sql.NullString
			osName     sql.NullString
			device     sql.NullString
			banner     sql.NullString
			cpesJSON   sql.NullString
			verify     sql.NullString
			lastSeen   sql.NullString
			sourceTool sql.NullString
		)
		if err := rows.Scan(
			&item.EndpointID,
			&item.IP,
			&item.Protocol,
			&item.Port,
			&portState,
			&confidence,
			&service,
			&product,
			&version,
			&info,
			&hostname,
			&osName,
			&device,
			&banner,
			&cpesJSON,
			&verify,
			&lastSeen,
			&sourceTool,
		); err != nil {
			return nil, err
		}
		item.CurrentPortState = nullStringPtr(portState)
		item.PortStateConfidence = nullIntPtr(confidence)
		item.CurrentService = nullStringPtr(service)
		item.CurrentProduct = nullStringPtr(product)
		item.CurrentVersion = nullStringPtr(version)
		item.CurrentInfo = nullStringPtr(info)
		item.CurrentHostname = nullStringPtr(hostname)
		item.CurrentOS = nullStringPtr(osName)
		item.CurrentDevice = nullStringPtr(device)
		item.CurrentBanner = nullStringPtr(banner)
		item.CurrentCPEsJSON = nullStringPtr(cpesJSON)
		item.VerificationState = nullStringDefault(verify, "none")
		item.LastSeenAt = nullStringPtr(lastSeen)
		item.SourceTool = nullStringPtr(sourceTool)
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListObservations 列出最近观测记录
func (q *QueryService) ListObservations(ctx context.Context, limit int) ([]ObservationRow, error) {
	return q.ListObservationsFiltered(ctx, QueryFilter{}, limit)
}

// ListObservationsFiltered 按条件筛选并列出观测记录
func (q *QueryService) ListObservationsFiltered(ctx context.Context, filter QueryFilter, limit int) ([]ObservationRow, error) {
	if limit <= 0 {
		limit = 100
	}

	query := strings.Builder{}
	query.WriteString(`
SELECT
  o.observation_id, o.run_id, o.tool, o.module_name, h.ip, e.protocol, e.port, o.route_used,
  o.action_type, o.raw_method, o.raw_status, o.request_summary, o.response_summary,
  o.rtt_ms, o.error_text, o.extra_json, o.observed_at
FROM observations o
JOIN hosts h ON h.host_id = o.host_id
LEFT JOIN endpoints e ON e.endpoint_id = o.endpoint_id`)

	conditions := make([]string, 0, 5)
	args := make([]any, 0, 6)
	if ip := strings.TrimSpace(filter.IP); ip != "" {
		conditions = append(conditions, "h.ip = ?")
		args = append(args, ip)
	}
	if filter.Port > 0 {
		conditions = append(conditions, "e.port = ?")
		args = append(args, filter.Port)
	}
	if protocol := strings.ToLower(strings.TrimSpace(filter.Protocol)); protocol != "" {
		conditions = append(conditions, "e.protocol = ?")
		args = append(args, protocol)
	}
	if tool := strings.TrimSpace(filter.Tool); tool != "" {
		conditions = append(conditions, "o.tool = ?")
		args = append(args, tool)
	}
	if runID := strings.TrimSpace(filter.RunID); runID != "" {
		conditions = append(conditions, "o.run_id = ?")
		args = append(args, runID)
	}

	appendConditions(&query, conditions)
	query.WriteString("\nORDER BY o.observed_at DESC\nLIMIT ?")
	args = append(args, limit)

	rows, err := q.store.DB().QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ObservationRow
	for rows.Next() {
		var (
			item            ObservationRow
			protocol        sql.NullString
			port            sql.NullInt64
			routeUsed       sql.NullString
			rawMethod       sql.NullString
			rawStatus       sql.NullString
			requestSummary  sql.NullString
			responseSummary sql.NullString
			rttMs           sql.NullFloat64
			errorText       sql.NullString
			extraJSON       sql.NullString
		)
		if err := rows.Scan(
			&item.ObservationID,
			&item.RunID,
			&item.Tool,
			&item.ModuleName,
			&item.IP,
			&protocol,
			&port,
			&routeUsed,
			&item.ActionType,
			&rawMethod,
			&rawStatus,
			&requestSummary,
			&responseSummary,
			&rttMs,
			&errorText,
			&extraJSON,
			&item.ObservedAt,
		); err != nil {
			return nil, err
		}
		item.Protocol = nullStringPtr(protocol)
		item.Port = nullIntPtr(port)
		item.RouteUsed = nullStringPtr(routeUsed)
		item.RawMethod = nullStringPtr(rawMethod)
		item.RawStatus = nullStringPtr(rawStatus)
		item.RequestSummary = nullStringPtr(requestSummary)
		item.ResponseSummary = nullStringPtr(responseSummary)
		item.RTTMs = nullFloatPtr(rttMs)
		item.ErrorText = nullStringPtr(errorText)
		item.ExtraJSON = nullStringPtr(extraJSON)
		items = append(items, item)
	}
	return items, rows.Err()
}

func appendConditions(builder *strings.Builder, conditions []string) {
	if len(conditions) == 0 {
		return
	}
	builder.WriteString("\nWHERE ")
	builder.WriteString(strings.Join(conditions, "\n  AND "))
}

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	value := v.String
	return &value
}

func nullIntPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	value := int(v.Int64)
	return &value
}

func nullStringDefault(v sql.NullString, fallback string) string {
	if v.Valid {
		return v.String
	}
	return fallback
}

func nullFloatPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	value := v.Float64
	return &value
}
