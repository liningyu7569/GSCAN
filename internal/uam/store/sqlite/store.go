package sqlite

import (
	"Going_Scan/internal/uam/domain"
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const timeLayout = time.RFC3339Nano

// Store UAM的SQLite持久化存储，封装所有数据库操作
type Store struct {
	db *sql.DB
}

// claimMeta 从claim表抽取的投影元信息（断言模式与声明时间），用于ShouldApply优先级比较
type claimMeta struct {
	AssertionMode string
	ClaimedAt     time.Time
}

// Open 打开SQLite数据库并设置WAL模式、外键等Pragma
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	}
	for _, stmt := range pragmas {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply pragma %q: %w", stmt, err)
		}
	}

	return &Store{db: db}, nil
}

// OpenExisting 打开已存在的 SQLite 数据库文件，若文件不存在则报错
func OpenExisting(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return Open(path)
}

// Close 关闭数据库连接
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB 返回底层 *sql.DB，供外部直接执行查询
func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// BeginTx 开启一个数据库事务
func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

// Migrate 执行schema SQL建表，幂等（使用CREATE IF NOT EXISTS）
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

// NewRunID 生成新的Run ID
func (s *Store) NewRunID() string {
	return newID("run")
}

// NewObservationID 生成新的Observation ID
func (s *Store) NewObservationID() string {
	return newID("obs")
}

// NewClaimID 生成新的Claim ID
func (s *Store) NewClaimID() string {
	return newID("claim")
}

// NewModuleResultID 生成新的ModuleResult ID
func (s *Store) NewModuleResultID() string {
	return newID("module")
}

// CreateRun 向runs表插入一条运行记录
func (s *Store) CreateRun(ctx context.Context, run domain.Run) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO runs (
  run_id, tool, module_name, commandline, started_at, finished_at,
  targets_json, profiles_json, ports_json, service_scan, extra_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID,
		run.Tool,
		run.ModuleName,
		run.Commandline,
		formatTime(run.StartedAt),
		formatTimePtr(run.FinishedAt),
		emptyToNil(run.TargetsJSON),
		emptyToNil(run.ProfilesJSON),
		emptyToNil(run.PortsJSON),
		boolToInt(run.ServiceScan),
		emptyToNil(run.ExtraJSON),
	)
	return err
}

// FinishRun 更新run的结束时间，标记运行完成
func (s *Store) FinishRun(ctx context.Context, runID string, finishedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished_at = ? WHERE run_id = ?`, formatTime(finishedAt), runID)
	return err
}

// EnsureHost 确保host记录存在（按IP幂等），同时初始化host_projection_current
func (s *Store) EnsureHost(ctx context.Context, tx *sql.Tx, host domain.Host) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO hosts (host_id, ip, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		host.HostID,
		host.IP,
		formatTime(host.FirstSeenAt),
		formatTime(host.LastSeenAt),
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO host_projection_current (host_id, verification_state)
VALUES (?, ?)
ON CONFLICT(host_id) DO NOTHING`,
		host.HostID,
		domain.VerificationNone,
	)
	return err
}

// EnsureEndpoint 确保endpoint记录存在（按host_id+protocol+port幂等），同时初始化endpoint_projection_current
func (s *Store) EnsureEndpoint(ctx context.Context, tx *sql.Tx, endpoint domain.Endpoint) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO endpoints (endpoint_id, host_id, protocol, port, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, protocol, port) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		endpoint.EndpointID,
		endpoint.HostID,
		endpoint.Protocol,
		endpoint.Port,
		formatTime(endpoint.FirstSeenAt),
		formatTime(endpoint.LastSeenAt),
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO endpoint_projection_current (endpoint_id, verification_state)
VALUES (?, ?)
ON CONFLICT(endpoint_id) DO NOTHING`,
		endpoint.EndpointID,
		domain.VerificationNone,
	)
	return err
}

// InsertObservation 向observations表插入一条观察记录
func (s *Store) InsertObservation(ctx context.Context, tx *sql.Tx, observation domain.Observation) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO observations (
  observation_id, run_id, tool, module_name, host_id, endpoint_id,
  route_used, action_type, raw_method, raw_status, request_summary,
  response_summary, rtt_ms, error_text, observed_at, extra_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observation.ObservationID,
		observation.RunID,
		observation.Tool,
		observation.ModuleName,
		observation.HostID,
		stringPtrValue(observation.EndpointID),
		stringPtrValue(observation.RouteUsed),
		observation.ActionType,
		emptyToNil(observation.RawMethod),
		emptyToNil(observation.RawStatus),
		emptyToNil(observation.RequestSummary),
		emptyToNil(observation.ResponseSummary),
		floatPtrValue(observation.RTTMs),
		emptyToNil(observation.ErrorText),
		formatTime(observation.ObservedAt),
		emptyToNil(observation.ExtraJSON),
	)
	return err
}

// InsertClaims 批量向claims表插入断言记录
func (s *Store) InsertClaims(ctx context.Context, tx *sql.Tx, claims []domain.Claim) error {
	for _, claim := range claims {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO claims (
  claim_id, observation_id, subject_type, subject_id, namespace, name,
  value_text, value_json, confidence, assertion_mode, claimed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			claim.ClaimID,
			claim.ObservationID,
			claim.SubjectType,
			claim.SubjectID,
			claim.Namespace,
			claim.Name,
			stringPtrValue(claim.ValueText),
			stringPtrValue(claim.ValueJSON),
			claim.Confidence,
			claim.AssertionMode,
			formatTime(claim.ClaimedAt),
		); err != nil {
			return err
		}
	}
	return nil
}

// InsertModuleResult 向module_results表插入一条模块产出记录
func (s *Store) InsertModuleResult(ctx context.Context, tx *sql.Tx, result domain.ModuleResult) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO module_results (
  module_result_id, run_id, observation_id, subject_type, subject_id,
  module_name, schema_version, data_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ModuleResultID,
		result.RunID,
		stringPtrValue(result.ObservationID),
		result.SubjectType,
		result.SubjectID,
		result.ModuleName,
		result.SchemaVersion,
		result.DataJSON,
		formatTime(result.CreatedAt),
	)
	return err
}

// LoadHostProjection 读取host_projection_current及关联的claim元信息，用于优先级比较
func (s *Store) LoadHostProjection(ctx context.Context, tx *sql.Tx, hostID string) (domain.HostProjectionCurrent, *claimMeta, error) {
	row := tx.QueryRowContext(ctx, `
SELECT
  hp.current_reachability,
  hp.reachability_confidence,
  hp.verification_state,
  hp.last_seen_at,
  hp.last_claim_id,
  hp.last_observation_id,
  hp.source_tool,
  c.assertion_mode,
  c.claimed_at
FROM host_projection_current hp
LEFT JOIN claims c ON c.claim_id = hp.last_claim_id
WHERE hp.host_id = ?`, hostID)

	var current domain.HostProjectionCurrent
	current.HostID = hostID
	current.VerificationState = domain.VerificationNone

	var (
		reachability sql.NullString
		confidence   sql.NullInt64
		verification sql.NullString
		lastSeen     sql.NullString
		lastClaimID  sql.NullString
		lastObsID    sql.NullString
		sourceTool   sql.NullString
		assertion    sql.NullString
		claimedAt    sql.NullString
	)
	if err := row.Scan(
		&reachability,
		&confidence,
		&verification,
		&lastSeen,
		&lastClaimID,
		&lastObsID,
		&sourceTool,
		&assertion,
		&claimedAt,
	); err != nil {
		return current, nil, err
	}

	current.CurrentReachability = nullStringPtr(reachability)
	current.ReachabilityConfidence = nullIntPtr(confidence)
	current.VerificationState = nullStringDefault(verification, domain.VerificationNone)
	current.LastSeenAt = nullTimePtr(lastSeen)
	current.LastClaimID = nullStringPtr(lastClaimID)
	current.LastObservationID = nullStringPtr(lastObsID)
	current.SourceTool = nullStringPtr(sourceTool)

	return current, buildClaimMeta(assertion, claimedAt), nil
}

// SaveHostProjection 写入或更新host_projection_current记录
func (s *Store) SaveHostProjection(ctx context.Context, tx *sql.Tx, current domain.HostProjectionCurrent) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO host_projection_current (
  host_id, current_reachability, reachability_confidence, verification_state,
  last_seen_at, last_claim_id, last_observation_id, source_tool
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id) DO UPDATE SET
  current_reachability = excluded.current_reachability,
  reachability_confidence = excluded.reachability_confidence,
  verification_state = excluded.verification_state,
  last_seen_at = excluded.last_seen_at,
  last_claim_id = excluded.last_claim_id,
  last_observation_id = excluded.last_observation_id,
  source_tool = excluded.source_tool`,
		current.HostID,
		stringPtrValue(current.CurrentReachability),
		intPtrValue(current.ReachabilityConfidence),
		current.VerificationState,
		timePtrValue(current.LastSeenAt),
		stringPtrValue(current.LastClaimID),
		stringPtrValue(current.LastObservationID),
		stringPtrValue(current.SourceTool),
	)
	return err
}

// LoadEndpointProjection 读取endpoint_projection_current及关联的claim元信息，用于优先级比较
func (s *Store) LoadEndpointProjection(ctx context.Context, tx *sql.Tx, endpointID string) (domain.EndpointProjectionCurrent, *claimMeta, error) {
	row := tx.QueryRowContext(ctx, `
SELECT
  ep.current_port_state,
  ep.port_state_confidence,
  ep.current_service,
  ep.current_product,
  ep.current_version,
  ep.current_info,
  ep.current_hostname,
  ep.current_os,
  ep.current_device,
  ep.current_banner,
  ep.current_cpes_json,
  ep.verification_state,
  ep.last_seen_at,
  ep.last_claim_id,
  ep.last_observation_id,
  ep.source_tool,
  c.assertion_mode,
  c.claimed_at
FROM endpoint_projection_current ep
LEFT JOIN claims c ON c.claim_id = ep.last_claim_id
WHERE ep.endpoint_id = ?`, endpointID)

	var current domain.EndpointProjectionCurrent
	current.EndpointID = endpointID
	current.VerificationState = domain.VerificationNone

	var (
		portState      sql.NullString
		portConfidence sql.NullInt64
		service        sql.NullString
		product        sql.NullString
		version        sql.NullString
		info           sql.NullString
		hostname       sql.NullString
		osName         sql.NullString
		device         sql.NullString
		banner         sql.NullString
		cpesJSON       sql.NullString
		verification   sql.NullString
		lastSeen       sql.NullString
		lastClaimID    sql.NullString
		lastObsID      sql.NullString
		sourceTool     sql.NullString
		assertion      sql.NullString
		claimedAt      sql.NullString
	)
	if err := row.Scan(
		&portState,
		&portConfidence,
		&service,
		&product,
		&version,
		&info,
		&hostname,
		&osName,
		&device,
		&banner,
		&cpesJSON,
		&verification,
		&lastSeen,
		&lastClaimID,
		&lastObsID,
		&sourceTool,
		&assertion,
		&claimedAt,
	); err != nil {
		return current, nil, err
	}

	current.CurrentPortState = nullStringPtr(portState)
	current.PortStateConfidence = nullIntPtr(portConfidence)
	current.CurrentService = nullStringPtr(service)
	current.CurrentProduct = nullStringPtr(product)
	current.CurrentVersion = nullStringPtr(version)
	current.CurrentInfo = nullStringPtr(info)
	current.CurrentHostname = nullStringPtr(hostname)
	current.CurrentOS = nullStringPtr(osName)
	current.CurrentDevice = nullStringPtr(device)
	current.CurrentBanner = nullStringPtr(banner)
	current.CurrentCPEsJSON = nullStringPtr(cpesJSON)
	current.VerificationState = nullStringDefault(verification, domain.VerificationNone)
	current.LastSeenAt = nullTimePtr(lastSeen)
	current.LastClaimID = nullStringPtr(lastClaimID)
	current.LastObservationID = nullStringPtr(lastObsID)
	current.SourceTool = nullStringPtr(sourceTool)

	return current, buildClaimMeta(assertion, claimedAt), nil
}

// SaveEndpointProjection 写入或更新endpoint_projection_current记录
func (s *Store) SaveEndpointProjection(ctx context.Context, tx *sql.Tx, current domain.EndpointProjectionCurrent) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO endpoint_projection_current (
  endpoint_id, current_port_state, port_state_confidence, current_service,
  current_product, current_version, current_info, current_hostname,
  current_os, current_device, current_banner, current_cpes_json,
  verification_state, last_seen_at, last_claim_id, last_observation_id,
  source_tool
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(endpoint_id) DO UPDATE SET
  current_port_state = excluded.current_port_state,
  port_state_confidence = excluded.port_state_confidence,
  current_service = excluded.current_service,
  current_product = excluded.current_product,
  current_version = excluded.current_version,
  current_info = excluded.current_info,
  current_hostname = excluded.current_hostname,
  current_os = excluded.current_os,
  current_device = excluded.current_device,
  current_banner = excluded.current_banner,
  current_cpes_json = excluded.current_cpes_json,
  verification_state = excluded.verification_state,
  last_seen_at = excluded.last_seen_at,
  last_claim_id = excluded.last_claim_id,
  last_observation_id = excluded.last_observation_id,
  source_tool = excluded.source_tool`,
		current.EndpointID,
		stringPtrValue(current.CurrentPortState),
		intPtrValue(current.PortStateConfidence),
		stringPtrValue(current.CurrentService),
		stringPtrValue(current.CurrentProduct),
		stringPtrValue(current.CurrentVersion),
		stringPtrValue(current.CurrentInfo),
		stringPtrValue(current.CurrentHostname),
		stringPtrValue(current.CurrentOS),
		stringPtrValue(current.CurrentDevice),
		stringPtrValue(current.CurrentBanner),
		stringPtrValue(current.CurrentCPEsJSON),
		current.VerificationState,
		timePtrValue(current.LastSeenAt),
		stringPtrValue(current.LastClaimID),
		stringPtrValue(current.LastObservationID),
		stringPtrValue(current.SourceTool),
	)
	return err
}

// formatTime 将时间格式化为UTC RFC3339Nano字符串
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// formatTimePtr 将*time.Time格式化为字符串或nil
func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// timePtrValue 将*time.Time转为可写入SQL的值（字符串或nil）
func timePtrValue(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// boolToInt 将bool转为int（SQLite存储用0/1）
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func emptyToNil(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// stringPtrValue 将*string转为可写入SQL的值，空字符串视为nil
func stringPtrValue(v *string) any {
	if v == nil || *v == "" {
		return nil
	}
	return *v
}

// intPtrValue 将*int转为可写入SQL的值
func intPtrValue(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

// floatPtrValue 将*float64转为可写入SQL的值
func floatPtrValue(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

// nullStringPtr 将sql.NullString转为*string
func nullStringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	value := v.String
	return &value
}

// nullIntPtr 将sql.NullInt64转为*int
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

// nullTimePtr 将数据库时间字符串解析为*time.Time
func nullTimePtr(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	parsed, err := time.Parse(timeLayout, v.String)
	if err != nil {
		return nil
	}
	return &parsed
}

// buildClaimMeta 从数据库字段构建claimMeta结构体
func buildClaimMeta(assertion sql.NullString, claimedAt sql.NullString) *claimMeta {
	if !assertion.Valid || !claimedAt.Valid || claimedAt.String == "" {
		return nil
	}
	parsed, err := time.Parse(timeLayout, claimedAt.String)
	if err != nil {
		return nil
	}
	return &claimMeta{
		AssertionMode: assertion.String,
		ClaimedAt:     parsed,
	}
}
