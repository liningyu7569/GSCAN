package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGSIngesterPersistsRunAndAssets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := NewGSIngester(ctx, dbPath, RunMetadata{
		Command:      "goscan scan 192.0.2.10 --syn -V -p 80",
		Targets:      []string{"192.0.2.10"},
		Ports:        []int{80},
		Profiles:     []string{"tcp-syn"},
		ServiceScan:  true,
		OutputFile:   "report.json",
		OutputFormat: "json",
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}

	if err := ingester.IngestResult(ctx, ScanResult{
		IP:       "192.0.2.10",
		Port:     80,
		Protocol: "tcp",
		Method:   "tcp-window",
		State:    "open",
	}); err != nil {
		t.Fatalf("IngestResult window returned error: %v", err)
	}

	if err := ingester.IngestResult(ctx, ScanResult{
		IP:       "192.0.2.10",
		Port:     80,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "http",
		Product:  "Apache httpd",
		Version:  "2.4.58",
		Info:     "Ubuntu",
		Hostname: "edge-1",
		OS:       "Linux",
		Device:   "web server",
		CPEs:     []string{"cpe:/a:apache:http_server:2.4.58"},
		Banner:   "Apache",
	}); err != nil {
		t.Fatalf("IngestResult syn returned error: %v", err)
	}

	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runCount); err != nil {
		t.Fatalf("query runs count returned error: %v", err)
	}
	if runCount != 1 {
		t.Fatalf("unexpected run count: got %d want 1", runCount)
	}

	var finishedAt sql.NullString
	if err := db.QueryRow(`SELECT finished_at FROM runs LIMIT 1`).Scan(&finishedAt); err != nil {
		t.Fatalf("query finished_at returned error: %v", err)
	}
	if !finishedAt.Valid || finishedAt.String == "" {
		t.Fatal("expected runs.finished_at to be populated")
	}

	var (
		currentPortState string
		currentService   sql.NullString
		currentProduct   sql.NullString
		currentVersion   sql.NullString
		currentBanner    sql.NullString
	)
	if err := db.QueryRow(`
SELECT current_port_state, current_service, current_product, current_version, current_banner
FROM endpoint_projection_current LIMIT 1`).Scan(
		&currentPortState,
		&currentService,
		&currentProduct,
		&currentVersion,
		&currentBanner,
	); err != nil {
		t.Fatalf("query endpoint projection returned error: %v", err)
	}
	if currentPortState != "open" {
		t.Fatalf("unexpected endpoint projection state: got %q want open", currentPortState)
	}
	if currentService.String != "http" || currentProduct.String != "Apache httpd" || currentVersion.String != "2.4.58" || currentBanner.String != "Apache" {
		t.Fatalf("unexpected endpoint fingerprint projection: service=%q product=%q version=%q banner=%q", currentService.String, currentProduct.String, currentVersion.String, currentBanner.String)
	}

	var reachability sql.NullString
	if err := db.QueryRow(`SELECT current_reachability FROM host_projection_current LIMIT 1`).Scan(&reachability); err != nil {
		t.Fatalf("query host projection returned error: %v", err)
	}
	if reachability.String != "reachable" {
		t.Fatalf("unexpected host reachability: got %q want reachable", reachability.String)
	}

	var observationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&observationCount); err != nil {
		t.Fatalf("query observations count returned error: %v", err)
	}
	if observationCount != 2 {
		t.Fatalf("unexpected observation count: got %d want 2", observationCount)
	}
}

func TestGSIngesterNormalizesWindowOpenToLikelyOpen(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := NewGSIngester(ctx, dbPath, RunMetadata{
		Command:     "goscan scan 192.0.2.11 --window -p 443",
		Targets:     []string{"192.0.2.11"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-window"},
		ServiceScan: false,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}

	if err := ingester.IngestResult(ctx, ScanResult{
		IP:       "192.0.2.11",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-window",
		State:    "open",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}

	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var (
		portState     string
		assertionMode string
	)
	if err := db.QueryRow(`SELECT current_port_state FROM endpoint_projection_current LIMIT 1`).Scan(&portState); err != nil {
		t.Fatalf("query endpoint projection returned error: %v", err)
	}
	if portState != "likely_open" {
		t.Fatalf("unexpected normalized port state: got %q want likely_open", portState)
	}

	if err := db.QueryRow(`
SELECT assertion_mode
FROM claims
WHERE namespace = 'network' AND name = 'port_state'
LIMIT 1`).Scan(&assertionMode); err != nil {
		t.Fatalf("query port_state claim returned error: %v", err)
	}
	if assertionMode != "inferred" {
		t.Fatalf("unexpected assertion mode: got %q want inferred", assertionMode)
	}
}

func TestGSIngesterSupportsDiscoveryAndServiceEnrichment(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := NewGSIngester(ctx, dbPath, RunMetadata{
		Command:     "goscan scan 203.0.113.40 --syn -V -p 443",
		Targets:     []string{"203.0.113.40"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}

	if err := ingester.IngestDiscovery(ctx, GSDiscoveryResult{
		IP:       "203.0.113.40",
		Method:   "icmp-echo",
		Status:   "alive",
		Protocol: "icmp",
	}); err != nil {
		t.Fatalf("IngestDiscovery returned error: %v", err)
	}

	if err := ingester.IngestResult(ctx, ScanResult{
		IP:       "203.0.113.40",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}

	if err := ingester.IngestServiceResult(ctx, ScanResult{
		IP:       "203.0.113.40",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
		Product:  "nginx",
		Banner:   "nginx",
	}); err != nil {
		t.Fatalf("IngestServiceResult returned error: %v", err)
	}

	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var observationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&observationCount); err != nil {
		t.Fatalf("query observations count returned error: %v", err)
	}
	if observationCount != 3 {
		t.Fatalf("unexpected observation count: got %d want 3", observationCount)
	}

	var serviceName sql.NullString
	if err := db.QueryRow(`SELECT current_service FROM endpoint_projection_current LIMIT 1`).Scan(&serviceName); err != nil {
		t.Fatalf("query endpoint projection returned error: %v", err)
	}
	if serviceName.String != "https" {
		t.Fatalf("unexpected service projection: got %q want https", serviceName.String)
	}
}
