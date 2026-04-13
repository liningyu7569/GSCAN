package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGPingIngesterOverrideBeatsGSProjection(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	gs, err := NewGSIngester(ctx, dbPath, RunMetadata{
		Command:     "goscan scan 198.51.100.10 --syn -V -p 443",
		Targets:     []string{"198.51.100.10"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	if err := gs.IngestResult(ctx, ScanResult{
		IP:       "198.51.100.10",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
		Banner:   "nginx",
	}); err != nil {
		t.Fatalf("GS IngestResult returned error: %v", err)
	}
	if err := gs.Close(ctx); err != nil {
		t.Fatalf("GS Close returned error: %v", err)
	}

	gping, err := NewGPingIngester(ctx, dbPath, GPingRunMetadata{
		Command:  "gping app https://198.51.100.10/health",
		Targets:  []string{"198.51.100.10"},
		Profiles: []string{"app"},
		Ports:    []int{443},
	})
	if err != nil {
		t.Fatalf("NewGPingIngester returned error: %v", err)
	}
	if err := gping.IngestObservation(ctx, GPingObservationInput{
		IP:              "198.51.100.10",
		Protocol:        "tcp",
		Port:            443,
		RouteUsed:       domain.RouteApp,
		ActionType:      domain.ActionRequest,
		RawMethod:       "http-get",
		RawStatus:       "success",
		ResponseSummary: "status=200 server=envoy",
		Claims: []normalize.GPingClaimInput{
			{
				Namespace:     "user",
				Name:          "verification_state",
				ValueText:     domain.VerificationConfirmed,
				Confidence:    100,
				AssertionMode: domain.AssertionManual,
			},
			{
				Namespace:     "user",
				Name:          "override_service_name",
				ValueText:     "envoy",
				Confidence:    100,
				AssertionMode: domain.AssertionOverride,
			},
		},
	}); err != nil {
		t.Fatalf("GPing IngestObservation returned error: %v", err)
	}
	if err := gping.Close(ctx); err != nil {
		t.Fatalf("GPing Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var (
		serviceName       sql.NullString
		verificationState string
		sourceTool        sql.NullString
	)
	if err := db.QueryRow(`
SELECT current_service, verification_state, source_tool
FROM endpoint_projection_current
LIMIT 1`).Scan(&serviceName, &verificationState, &sourceTool); err != nil {
		t.Fatalf("query endpoint projection returned error: %v", err)
	}
	if serviceName.String != "envoy" {
		t.Fatalf("unexpected overridden service name: got %q want envoy", serviceName.String)
	}
	if verificationState != domain.VerificationConfirmed {
		t.Fatalf("unexpected verification state: got %q want %q", verificationState, domain.VerificationConfirmed)
	}
	if sourceTool.String != domain.ToolGPing {
		t.Fatalf("unexpected projection source tool: got %q want %q", sourceTool.String, domain.ToolGPing)
	}
}

func TestModuleIngesterPersistsModuleResults(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	moduleIngester, err := NewModuleIngester(ctx, dbPath, "httpx", ModuleRunMetadata{
		Command: "httpx --json",
		Targets: []string{"203.0.113.20"},
		Ports:   []int{80},
	})
	if err != nil {
		t.Fatalf("NewModuleIngester returned error: %v", err)
	}

	if err := moduleIngester.IngestObservation(ctx, ModuleObservationInput{
		IP:              "203.0.113.20",
		Protocol:        "tcp",
		Port:            80,
		ModuleName:      "httpx",
		ActionType:      domain.ActionCollect,
		RawMethod:       "http-head",
		RawStatus:       "success",
		ResponseSummary: "status=200 title=Home",
		Claims: []normalize.ModuleClaimInput{
			{
				Namespace:     "service",
				Name:          "name",
				ValueText:     "http",
				Confidence:    90,
				AssertionMode: domain.AssertionObserved,
			},
			{
				Namespace:     "http",
				Name:          "status_code",
				ValueText:     "200",
				Confidence:    100,
				AssertionMode: domain.AssertionObserved,
			},
		},
		Results: []ModuleResultInput{
			{
				SchemaVersion: "v1",
				DataJSON:      `{"title":"Home","headers":{"server":"caddy"}}`,
			},
		},
	}); err != nil {
		t.Fatalf("Module IngestObservation returned error: %v", err)
	}
	if err := moduleIngester.Close(ctx); err != nil {
		t.Fatalf("Module Close returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	var moduleResultCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_results`).Scan(&moduleResultCount); err != nil {
		t.Fatalf("query module_results count returned error: %v", err)
	}
	if moduleResultCount != 1 {
		t.Fatalf("unexpected module_results count: got %d want 1", moduleResultCount)
	}

	var serviceName sql.NullString
	if err := db.QueryRow(`SELECT current_service FROM endpoint_projection_current LIMIT 1`).Scan(&serviceName); err != nil {
		t.Fatalf("query endpoint projection returned error: %v", err)
	}
	if serviceName.String != "http" {
		t.Fatalf("unexpected projected service: got %q want http", serviceName.String)
	}
}

func TestQueryServiceListsCurrentAssets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := NewGSIngester(ctx, dbPath, RunMetadata{
		Command:     "goscan scan 192.0.2.30 --syn -p 22",
		Targets:     []string{"192.0.2.30"},
		Ports:       []int{22},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: false,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	if err := ingester.IngestResult(ctx, ScanResult{
		IP:       "192.0.2.30",
		Port:     22,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	queryService, err := OpenQueryService(dbPath)
	if err != nil {
		t.Fatalf("OpenQueryService returned error: %v", err)
	}
	defer queryService.Close()

	runs, err := queryService.ListRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListRuns returned error: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("unexpected runs length: got %d want 1", len(runs))
	}

	hosts, err := queryService.ListHosts(ctx, 10)
	if err != nil {
		t.Fatalf("ListHosts returned error: %v", err)
	}
	if len(hosts) != 1 || hosts[0].IP != "192.0.2.30" {
		t.Fatalf("unexpected hosts result: %+v", hosts)
	}

	endpoints, err := queryService.ListEndpoints(ctx, 10)
	if err != nil {
		t.Fatalf("ListEndpoints returned error: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Port != 22 {
		t.Fatalf("unexpected endpoints result: %+v", endpoints)
	}

	observations, err := queryService.ListObservations(ctx, 10)
	if err != nil {
		t.Fatalf("ListObservations returned error: %v", err)
	}
	if len(observations) != 1 || observations[0].IP != "192.0.2.30" {
		t.Fatalf("unexpected observations result: %+v", observations)
	}

	filteredEndpoints, err := queryService.ListEndpointsFiltered(ctx, QueryFilter{
		IP:       "192.0.2.30",
		Port:     22,
		Protocol: "tcp",
	}, 10)
	if err != nil {
		t.Fatalf("ListEndpointsFiltered returned error: %v", err)
	}
	if len(filteredEndpoints) != 1 || filteredEndpoints[0].Port != 22 {
		t.Fatalf("unexpected filtered endpoints result: %+v", filteredEndpoints)
	}

	report, err := queryService.BuildHostReport(ctx, QueryFilter{
		IP:       "192.0.2.30",
		Port:     22,
		Protocol: "tcp",
	}, 20)
	if err != nil {
		t.Fatalf("BuildHostReport returned error: %v", err)
	}
	rendered := RenderHostReport(report)
	if !strings.Contains(rendered, "UAM Report for 192.0.2.30") {
		t.Fatalf("report missing header: %s", rendered)
	}
	if !strings.Contains(rendered, "22/tcp") || !strings.Contains(rendered, "tcp-syn -> open") {
		t.Fatalf("report missing endpoint facts: %s", rendered)
	}
}
