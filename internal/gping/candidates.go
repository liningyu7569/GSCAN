package gping

import (
	sqlitestore "Going_Scan/internal/uam/store/sqlite"
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ListCandidates 从 UAM 数据库中查询符合筛选条件的端点资产列表
func ListCandidates(ctx context.Context, opts Options, limit int) ([]Candidate, error) {
	if strings.TrimSpace(opts.UAMDBPath) == "" {
		return nil, fmt.Errorf("--uam-db is required when listing gping candidates")
	}
	if limit <= 0 {
		limit = 20
	}

	store, err := sqlitestore.OpenExisting(opts.UAMDBPath)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	query := strings.Builder{}
	query.WriteString(`
SELECT endpoint_id, ip, protocol, port, current_service, verification_state, last_seen_at, source_tool, current_product, current_version, current_banner
FROM v_endpoint_assets`)

	conditions := make([]string, 0, 6)
	args := make([]any, 0, 8)
	if ip := strings.TrimSpace(opts.IP); ip != "" {
		conditions = append(conditions, "ip = ?")
		args = append(args, ip)
	}
	if opts.Port > 0 {
		conditions = append(conditions, "port = ?")
		args = append(args, opts.Port)
	}
	if rawProtocol := strings.TrimSpace(opts.Protocol); rawProtocol != "" {
		protocol := normalizeProtocol(rawProtocol)
		if protocol != "icmp" {
			conditions = append(conditions, "protocol = ?")
			args = append(args, protocol)
		}
	}
	if service := strings.TrimSpace(opts.UAMService); service != "" {
		conditions = append(conditions, "current_service = ?")
		args = append(args, service)
	}
	if verify := normalizeVerificationState(opts.UAMVerify); verify != "" {
		conditions = append(conditions, "verification_state = ?")
		args = append(args, verify)
	}
	if len(conditions) == 0 {
		return nil, fmt.Errorf("at least one UAM selection filter is required")
	}

	query.WriteString("\nWHERE " + strings.Join(conditions, " AND "))
	query.WriteString("\nORDER BY COALESCE(last_seen_at, '') DESC, ip, port, protocol\nLIMIT ?")
	args = append(args, limit)

	rows, err := store.DB().QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Candidate, 0, limit)
	for rows.Next() {
		var (
			item           Candidate
			currentService sql.NullString
			lastSeenAt     sql.NullString
			sourceTool     sql.NullString
			currentProduct sql.NullString
			currentVersion sql.NullString
			currentBanner  sql.NullString
		)
		if err := rows.Scan(
			&item.EndpointID,
			&item.IP,
			&item.Protocol,
			&item.Port,
			&currentService,
			&item.VerificationState,
			&lastSeenAt,
			&sourceTool,
			&currentProduct,
			&currentVersion,
			&currentBanner,
		); err != nil {
			return nil, err
		}
		item.CurrentService = strings.TrimSpace(currentService.String)
		item.LastSeenAt = strings.TrimSpace(lastSeenAt.String)
		item.SourceTool = strings.TrimSpace(sourceTool.String)
		item.CurrentProduct = strings.TrimSpace(currentProduct.String)
		item.CurrentVersion = strings.TrimSpace(currentVersion.String)
		item.CurrentBanner = strings.TrimSpace(currentBanner.String)
		item.SuggestedTemplates = SuggestTemplatesForCandidate(item)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
