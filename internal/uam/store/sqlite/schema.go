package sqlite

const schemaSQL = `
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  tool TEXT NOT NULL CHECK (tool IN ('gs', 'gping', 'module')),
  module_name TEXT NOT NULL,
  commandline TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  targets_json TEXT,
  profiles_json TEXT,
  ports_json TEXT,
  service_scan INTEGER NOT NULL DEFAULT 0 CHECK (service_scan IN (0,1)),
  extra_json TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  host_id TEXT PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
  endpoint_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port >= 0 AND port <= 65535),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(host_id, protocol, port),
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations (
  observation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  tool TEXT NOT NULL CHECK (tool IN ('gs', 'gping', 'module')),
  module_name TEXT NOT NULL,
  host_id TEXT NOT NULL,
  endpoint_id TEXT,
  route_used TEXT CHECK (route_used IN ('stack', 'raw', 'app') OR route_used IS NULL),
  action_type TEXT NOT NULL CHECK (
    action_type IN ('reach', 'probe', 'handshake', 'request', 'inject', 'scan', 'collect')
  ),
  raw_method TEXT,
  raw_status TEXT,
  request_summary TEXT,
  response_summary TEXT,
  rtt_ms REAL,
  error_text TEXT,
  observed_at TEXT NOT NULL,
  extra_json TEXT,
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS claims (
  claim_id TEXT PRIMARY KEY,
  observation_id TEXT NOT NULL,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('host', 'endpoint')),
  subject_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  value_text TEXT,
  value_json TEXT,
  confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
  assertion_mode TEXT NOT NULL CHECK (
    assertion_mode IN ('observed', 'inferred', 'manual', 'override')
  ),
  claimed_at TEXT NOT NULL,
  FOREIGN KEY (observation_id) REFERENCES observations(observation_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_projection_current (
  host_id TEXT PRIMARY KEY,
  current_reachability TEXT CHECK (
    current_reachability IN ('reachable', 'unreachable', 'unknown')
  ),
  reachability_confidence INTEGER CHECK (
    reachability_confidence >= 0 AND reachability_confidence <= 100
  ),
  verification_state TEXT NOT NULL DEFAULT 'none' CHECK (
    verification_state IN ('none', 'pending', 'confirmed', 'overridden')
  ),
  last_seen_at TEXT,
  last_claim_id TEXT,
  last_observation_id TEXT,
  source_tool TEXT CHECK (source_tool IN ('gs', 'gping', 'module')),
  FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
  FOREIGN KEY (last_claim_id) REFERENCES claims(claim_id) ON DELETE SET NULL,
  FOREIGN KEY (last_observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS endpoint_projection_current (
  endpoint_id TEXT PRIMARY KEY,
  current_port_state TEXT CHECK (
    current_port_state IN ('open', 'closed', 'filtered', 'unfiltered', 'likely_open', 'unknown')
  ),
  port_state_confidence INTEGER CHECK (
    port_state_confidence >= 0 AND port_state_confidence <= 100
  ),
  current_service TEXT,
  current_product TEXT,
  current_version TEXT,
  current_info TEXT,
  current_hostname TEXT,
  current_os TEXT,
  current_device TEXT,
  current_banner TEXT,
  current_cpes_json TEXT,
  verification_state TEXT NOT NULL DEFAULT 'none' CHECK (
    verification_state IN ('none', 'pending', 'confirmed', 'overridden')
  ),
  last_seen_at TEXT,
  last_claim_id TEXT,
  last_observation_id TEXT,
  source_tool TEXT CHECK (source_tool IN ('gs', 'gping', 'module')),
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
  FOREIGN KEY (last_claim_id) REFERENCES claims(claim_id) ON DELETE SET NULL,
  FOREIGN KEY (last_observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS module_results (
  module_result_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  observation_id TEXT,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('host', 'endpoint')),
  subject_id TEXT NOT NULL,
  module_name TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
  FOREIGN KEY (observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);

CREATE INDEX IF NOT EXISTS idx_endpoints_host_protocol_port
ON endpoints(host_id, protocol, port);

CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_observations_host ON observations(host_id);
CREATE INDEX IF NOT EXISTS idx_observations_endpoint ON observations(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_observations_tool_module_time
ON observations(tool, module_name, observed_at);

CREATE INDEX IF NOT EXISTS idx_claims_observation ON claims(observation_id);
CREATE INDEX IF NOT EXISTS idx_claims_subject ON claims(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_claims_ns_name ON claims(namespace, name);
CREATE INDEX IF NOT EXISTS idx_claims_subject_time
ON claims(subject_type, subject_id, claimed_at);

CREATE INDEX IF NOT EXISTS idx_module_results_subject
ON module_results(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_module_results_module
ON module_results(module_name, created_at);

CREATE VIEW IF NOT EXISTS v_endpoint_assets AS
SELECT
  e.endpoint_id,
  h.ip,
  e.protocol,
  e.port,
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
  ep.source_tool
FROM endpoints e
JOIN hosts h ON h.host_id = e.host_id
LEFT JOIN endpoint_projection_current ep ON ep.endpoint_id = e.endpoint_id;

CREATE VIEW IF NOT EXISTS v_host_assets AS
SELECT
  h.host_id,
  h.ip,
  hp.current_reachability,
  hp.reachability_confidence,
  hp.verification_state,
  hp.last_seen_at,
  hp.source_tool
FROM hosts h
LEFT JOIN host_projection_current hp ON hp.host_id = h.host_id;

CREATE VIEW IF NOT EXISTS v_recent_observations AS
SELECT
  o.observation_id,
  o.tool,
  o.module_name,
  h.ip,
  e.protocol,
  e.port,
  o.route_used,
  o.action_type,
  o.raw_method,
  o.raw_status,
  o.request_summary,
  o.response_summary,
  o.rtt_ms,
  o.error_text,
  o.observed_at
FROM observations o
JOIN hosts h ON h.host_id = o.host_id
LEFT JOIN endpoints e ON e.endpoint_id = o.endpoint_id;
`
