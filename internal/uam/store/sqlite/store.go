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

type Store struct {
	db *sql.DB
}

type claimMeta struct {
	AssertionMode string
	ClaimedAt     time.Time
}

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

func OpenExisting(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return Open(path)
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *Store) NewRunID() string {
	return newID("run")
}

func (s *Store) NewObservationID() string {
	return newID("obs")
}

func (s *Store) NewClaimID() string {
	return newID("claim")
}

func (s *Store) NewModuleResultID() string {
	return newID("module")
}

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

func (s *Store) FinishRun(ctx context.Context, runID string, finishedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished_at = ? WHERE run_id = ?`, formatTime(finishedAt), runID)
	return err
}

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

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func timePtrValue(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

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

func stringPtrValue(v *string) any {
	if v == nil || *v == "" {
		return nil
	}
	return *v
}

func intPtrValue(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func floatPtrValue(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
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
