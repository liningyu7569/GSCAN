package gping

import (
	uamservice "Going_Scan/internal/uam/service"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlanBuiltInTemplate(t *testing.T) {
	actions, name, err := Plan(Options{
		TemplateName: "uam/https-enrich",
		Vars: map[string]string{
			"health_path": "/healthz",
		},
		InsecureSkipVerify: true,
	}, TargetContext{
		IP:         "127.0.0.1",
		Port:       443,
		Protocol:   "tcp",
		Scheme:     "https",
		Host:       "example.internal",
		HostHeader: "example.internal",
		SNI:        "example.internal",
		Path:       "/",
		Source:     "uam",
	})
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	if name != "uam/https-enrich" {
		t.Fatalf("unexpected template name: got %q", name)
	}
	if len(actions) != 4 {
		t.Fatalf("unexpected action count: got %d want 4", len(actions))
	}
	if actions[3].Method != "http-get" {
		t.Fatalf("unexpected final action method: got %q want http-get", actions[3].Method)
	}
	if !strings.Contains(actions[3].URL, "/healthz") {
		t.Fatalf("unexpected expanded action url: %q", actions[3].URL)
	}
}

func TestBuildActionURLPreservesQueryString(t *testing.T) {
	url := buildActionURL(TargetContext{
		IP:         "127.0.0.1",
		Port:       8443,
		Protocol:   "tcp",
		Scheme:     "https",
		Host:       "example.internal",
		HostHeader: "example.internal",
		Path:       "/",
	}, "/health?check=ready&full=true")
	if url != "https://example.internal:8443/health?check=ready&full=true" {
		t.Fatalf("unexpected built action url: %q", url)
	}
}

func TestRunTCPConnectOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline: "goscan gping --ip 127.0.0.1 --port test --method tcp-connect",
		IP:          "127.0.0.1",
		Port:        port,
		Route:       "stack",
		Method:      "tcp-connect",
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	if result.Reports[0].RawStatus != "open" {
		t.Fatalf("unexpected tcp-connect status: got %q want open", result.Reports[0].RawStatus)
	}
	if !hasClaim(result.Reports[0], "network", "port_state", "open") {
		t.Fatalf("expected open network.port_state claim, got %+v", result.Reports[0].Claims)
	}
}

func TestRunBannerReadWritesBannerFactsToUAM(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 ProFTPD 1.3.5 Server\r\n"))
	}()

	dbPath := filepath.Join(t.TempDir(), "uam.db")
	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline: "goscan gping --ip 127.0.0.1 --port test --method banner-read",
		IP:          "127.0.0.1",
		Port:        port,
		Route:       "stack",
		Method:      "banner-read",
		UAMDBPath:   dbPath,
		WriteUAM:    true,
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	if result.Reports[0].RawStatus != "banner" {
		t.Fatalf("unexpected banner-read status: got %q want banner", result.Reports[0].RawStatus)
	}
	if !hasClaim(result.Reports[0], "service", "banner", "220 ProFTPD 1.3.5 Server\r\n") {
		t.Fatalf("expected service.banner claim, got %+v", result.Reports[0].Claims)
	}
	if !hasClaim(result.Reports[0], "service", "product", "ProFTPD") {
		t.Fatalf("expected service.product claim, got %+v", result.Reports[0].Claims)
	}
	if !hasClaim(result.Reports[0], "service", "version", "1.3.5") {
		t.Fatalf("expected service.version claim, got %+v", result.Reports[0].Claims)
	}

	queryService, err := uamservice.OpenQueryService(dbPath)
	if err != nil {
		t.Fatalf("OpenQueryService returned error: %v", err)
	}
	defer queryService.Close()

	endpoints, err := queryService.ListEndpointsFiltered(context.Background(), uamservice.QueryFilter{
		IP:       "127.0.0.1",
		Port:     port,
		Protocol: "tcp",
		Tool:     "gping",
	}, 10)
	if err != nil {
		t.Fatalf("ListEndpointsFiltered returned error: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("unexpected endpoint result length: got %d want 1", len(endpoints))
	}
	if endpoints[0].CurrentBanner == nil || !strings.Contains(*endpoints[0].CurrentBanner, "ProFTPD") {
		t.Fatalf("unexpected current banner: %+v", endpoints[0].CurrentBanner)
	}
	if endpoints[0].CurrentProduct == nil || *endpoints[0].CurrentProduct != "ProFTPD" {
		t.Fatalf("unexpected current product: %+v", endpoints[0].CurrentProduct)
	}
}

func TestResolveTargetFromUAMServiceFilter(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 198.51.100.10 --syn -V -p 443",
		Targets:     []string{"198.51.100.10"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	if err := ingester.IngestResult(ctx, uamservice.ScanResult{
		IP:       "198.51.100.10",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	target, err := ResolveTarget(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
		HostHeader: "app.internal",
		SNI:        "app.internal",
		Path:       "/health",
		PickFirst:  true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if target.Source != "uam-query" {
		t.Fatalf("unexpected target source: got %q want uam-query", target.Source)
	}
	if target.HostHeader != "app.internal" || target.SNI != "app.internal" {
		t.Fatalf("target overrides not applied: %+v", target)
	}
	if !strings.Contains(target.URL, "/health") {
		t.Fatalf("unexpected overridden target url: %q", target.URL)
	}
}

func TestResolveTargetFromUAMFilterRequiresDisambiguation(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 198.51.100.0/24 --syn -V -p 443,8443",
		Targets:     []string{"198.51.100.20", "198.51.100.21"},
		Ports:       []int{443, 8443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	for _, item := range []uamservice.ScanResult{
		{IP: "198.51.100.20", Port: 443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
		{IP: "198.51.100.21", Port: 8443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
	} {
		if err := ingester.IngestResult(ctx, item); err != nil {
			t.Fatalf("IngestResult returned error: %v", err)
		}
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	_, err = ResolveTarget(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
	})
	if err == nil {
		t.Fatalf("expected ResolveTarget to fail when multiple endpoints match")
	}
	if !strings.Contains(err.Error(), "multiple UAM endpoints matched") {
		t.Fatalf("unexpected ResolveTarget error: %v", err)
	}
}

func TestResolveTargetFromUAMFilterPickIndex(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 198.51.100.0/24 --syn -V -p 443,8443",
		Targets:     []string{"198.51.100.20", "198.51.100.21"},
		Ports:       []int{443, 8443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	for _, item := range []uamservice.ScanResult{
		{IP: "198.51.100.20", Port: 443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
		{IP: "198.51.100.21", Port: 8443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
	} {
		if err := ingester.IngestResult(ctx, item); err != nil {
			t.Fatalf("IngestResult returned error: %v", err)
		}
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	candidates, err := ListCandidates(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
	}, 10)
	if err != nil {
		t.Fatalf("ListCandidates returned error: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("unexpected candidate length: got %d want 2", len(candidates))
	}

	target, err := ResolveTarget(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
		PickIndex:  2,
	})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if target.IP != candidates[1].IP || target.Port != candidates[1].Port {
		t.Fatalf("unexpected picked target: %+v", target)
	}
}

func TestResolveTargetUsesUAMSelectionWhenPickFirstIsSet(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 198.51.100.30 --syn -V -p 443,8443",
		Targets:     []string{"198.51.100.30"},
		Ports:       []int{443, 8443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	for _, item := range []uamservice.ScanResult{
		{IP: "198.51.100.30", Port: 443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
		{IP: "198.51.100.30", Port: 8443, Protocol: "tcp", Method: "tcp-syn", State: "open", Service: "https"},
	} {
		if err := ingester.IngestResult(ctx, item); err != nil {
			t.Fatalf("IngestResult returned error: %v", err)
		}
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	target, err := ResolveTarget(ctx, Options{
		UAMDBPath: dbPath,
		IP:        "198.51.100.30",
		PickFirst: true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if target.Source != "uam-query" {
		t.Fatalf("expected UAM query source, got %q", target.Source)
	}
}

func TestApplyActionProtocolInfersICMP(t *testing.T) {
	target := applyActionProtocol(TargetContext{
		IP:       "127.0.0.1",
		Port:     0,
		Protocol: "tcp",
		Scheme:   "http",
		URL:      "http://127.0.0.1/",
	}, []ActionUnit{
		{Route: "raw", Method: "icmp-echo-raw"},
	})
	if target.Protocol != "icmp" {
		t.Fatalf("unexpected inferred protocol: got %q want icmp", target.Protocol)
	}
	if target.URL != "" {
		t.Fatalf("icmp target should not keep url, got %q", target.URL)
	}
}

func TestListTemplateSummaries(t *testing.T) {
	items, err := ListTemplateSummaries()
	if err != nil {
		t.Fatalf("ListTemplateSummaries returned error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected built-in templates")
	}
	found := false
	for _, item := range items {
		if item.Name == "uam/https-enrich" {
			found = true
			if item.ActionCount != 4 {
				t.Fatalf("unexpected action count for %s: got %d want 4", item.Name, item.ActionCount)
			}
		}
	}
	if !found {
		t.Fatalf("expected uam/https-enrich to be listed")
	}
}

func TestListCandidates(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 203.0.113.10 --syn -V -p 443",
		Targets:     []string{"203.0.113.10"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	if err := ingester.IngestResult(ctx, uamservice.ScanResult{
		IP:       "203.0.113.10",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
		Product:  "envoy",
		Banner:   "envoy/1.29.0",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	items, err := ListCandidates(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
	}, 10)
	if err != nil {
		t.Fatalf("ListCandidates returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("unexpected candidate length: got %d want 1", len(items))
	}
	if items[0].CurrentProduct != "envoy" {
		t.Fatalf("unexpected candidate product: got %q want envoy", items[0].CurrentProduct)
	}
	if !containsString(items[0].SuggestedTemplates, "uam/https-enrich") {
		t.Fatalf("expected candidate template suggestions, got %+v", items[0].SuggestedTemplates)
	}
}

func TestSuggestTemplatesIncludesBannerReadForFTP(t *testing.T) {
	items := SuggestTemplates(TargetContext{
		IP:             "203.0.113.20",
		Port:           21,
		Protocol:       "tcp",
		CurrentService: "ftp",
	})
	if !containsString(items, "stack/basic-banner-read") {
		t.Fatalf("expected banner-read suggestion for ftp, got %+v", items)
	}
	if !containsString(items, "ftp/basic-confirm") || !containsString(items, "uam/ftp-enrich") {
		t.Fatalf("expected ftp template suggestions, got %+v", items)
	}
}

func TestSuggestTemplatesIncludesSSHAndRedisTemplates(t *testing.T) {
	sshItems := SuggestTemplates(TargetContext{
		IP:             "203.0.113.21",
		Port:           22,
		Protocol:       "tcp",
		CurrentService: "ssh",
	})
	if !containsString(sshItems, "ssh/basic-confirm") || !containsString(sshItems, "uam/ssh-enrich") {
		t.Fatalf("expected ssh suggestions, got %+v", sshItems)
	}

	redisItems := SuggestTemplates(TargetContext{
		IP:             "203.0.113.22",
		Port:           6379,
		Protocol:       "tcp",
		CurrentService: "redis",
	})
	if !containsString(redisItems, "redis/basic-confirm") || !containsString(redisItems, "uam/redis-enrich") {
		t.Fatalf("expected redis suggestions, got %+v", redisItems)
	}

	dnsItems := SuggestTemplates(TargetContext{
		IP:             "203.0.113.23",
		Port:           53,
		Protocol:       "udp",
		CurrentService: "dns",
	})
	if !containsString(dnsItems, "dns/basic-confirm") || !containsString(dnsItems, "uam/dns-enrich") {
		t.Fatalf("expected dns suggestions, got %+v", dnsItems)
	}

	smtpItems := SuggestTemplates(TargetContext{
		IP:             "203.0.113.24",
		Port:           25,
		Protocol:       "tcp",
		CurrentService: "smtp",
	})
	if !containsString(smtpItems, "smtp/basic-confirm") || !containsString(smtpItems, "uam/smtp-enrich") {
		t.Fatalf("expected smtp suggestions, got %+v", smtpItems)
	}
}

func TestPreviewWithoutActionShowsSuggestedTemplates(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	ingester, err := uamservice.NewGSIngester(ctx, dbPath, uamservice.RunMetadata{
		Command:     "goscan scan 203.0.113.11 --syn -V -p 443",
		Targets:     []string{"203.0.113.11"},
		Ports:       []int{443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
	})
	if err != nil {
		t.Fatalf("NewGSIngester returned error: %v", err)
	}
	if err := ingester.IngestResult(ctx, uamservice.ScanResult{
		IP:       "203.0.113.11",
		Port:     443,
		Protocol: "tcp",
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
		Product:  "envoy",
	}); err != nil {
		t.Fatalf("IngestResult returned error: %v", err)
	}
	if err := ingester.Close(ctx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	preview, err := Preview(ctx, Options{
		UAMDBPath:  dbPath,
		UAMService: "https",
		PickFirst:  true,
	})
	if err != nil {
		t.Fatalf("Preview returned error: %v", err)
	}
	if len(preview.Actions) != 0 {
		t.Fatalf("expected no planned actions, got %d", len(preview.Actions))
	}
	if preview.Target.CurrentProduct != "envoy" {
		t.Fatalf("unexpected hydrated product: got %q want envoy", preview.Target.CurrentProduct)
	}
	if !containsString(preview.SuggestedTemplates, "uam/https-enrich") {
		t.Fatalf("expected preview suggestions to include uam/https-enrich, got %+v", preview.SuggestedTemplates)
	}
	if !containsString(preview.SuggestedTemplates, "http/reverse-proxy-confirm") {
		t.Fatalf("expected preview suggestions to include http/reverse-proxy-confirm, got %+v", preview.SuggestedTemplates)
	}
}

func TestPreviewWithTemplateIncludesSuggestAndAssertions(t *testing.T) {
	preview, err := Preview(context.Background(), Options{
		Commandline:       "goscan gping --ip 203.0.113.12 --port 443 --template uam/https-enrich --assert confirmed --override-service envoy",
		IP:                "203.0.113.12",
		Port:              443,
		TemplateName:      "uam/https-enrich",
		VerificationState: "confirmed",
		OverrideService:   "envoy",
		Timeout:           2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Preview returned error: %v", err)
	}
	if preview.TemplateName != "uam/https-enrich" {
		t.Fatalf("unexpected template name: got %q", preview.TemplateName)
	}
	if len(preview.Actions) != 4 {
		t.Fatalf("unexpected preview action count: got %d want 4", len(preview.Actions))
	}
	if preview.TemplateSuggest["verification_state"] != "pending" {
		t.Fatalf("unexpected template suggest payload: %+v", preview.TemplateSuggest)
	}
	if !containsString(preview.OperatorAssertions, "user.verification_state=confirmed") {
		t.Fatalf("missing verification assertion: %+v", preview.OperatorAssertions)
	}
	if !containsString(preview.OperatorAssertions, "user.override_service_name=envoy") {
		t.Fatalf("missing override assertion: %+v", preview.OperatorAssertions)
	}
}

func TestRunHTTPGetWritesToUAM(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "envoy/1.29.0")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Gateway</title></head><body>ok</body></html>"))
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}
	port := parsed.Port()
	dbPath := filepath.Join(t.TempDir(), "uam.db")

	result, err := Run(context.Background(), Options{
		Commandline:        "goscan gping https://127.0.0.1 --method http-get",
		URL:                server.URL,
		Route:              "app",
		Method:             "http-get",
		InsecureSkipVerify: true,
		UAMDBPath:          dbPath,
		WriteUAM:           true,
		Timeout:            3 * time.Second,
		VerificationState:  "confirmed",
		OverrideService:    "envoy",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	if result.UAMRunID == "" {
		t.Fatalf("expected UAM run id to be set")
	}
	if !hasClaim(result.Reports[0], "http", "title", "Gateway") {
		t.Fatalf("expected http.title claim, got %+v", result.Reports[0].Claims)
	}

	queryService, err := uamservice.OpenQueryService(dbPath)
	if err != nil {
		t.Fatalf("OpenQueryService returned error: %v", err)
	}
	defer queryService.Close()

	endpoints, err := queryService.ListEndpointsFiltered(context.Background(), uamservice.QueryFilter{
		IP:       "127.0.0.1",
		Port:     mustParsePort(t, port),
		Protocol: "tcp",
		Tool:     "gping",
	}, 10)
	if err != nil {
		t.Fatalf("ListEndpointsFiltered returned error: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("unexpected endpoint result length: got %d want 1", len(endpoints))
	}
	if endpoints[0].CurrentService == nil || *endpoints[0].CurrentService != "envoy" {
		t.Fatalf("unexpected projected service: %+v", endpoints[0].CurrentService)
	}
	if endpoints[0].VerificationState != "confirmed" {
		t.Fatalf("unexpected verification state: got %q want confirmed", endpoints[0].VerificationState)
	}

	history, err := BuildHistory(context.Background(), dbPath, HistoryFilter{
		IP:       "127.0.0.1",
		Port:     mustParsePort(t, port),
		Protocol: "tcp",
	}, 10)
	if err != nil {
		t.Fatalf("BuildHistory returned error: %v", err)
	}
	if history.Endpoint == nil {
		t.Fatalf("expected current endpoint summary in history")
	}
	if len(history.Observations) != 1 {
		t.Fatalf("unexpected history observation length: got %d want 1", len(history.Observations))
	}
	if history.Observations[0].ExtraJSON == nil || *history.Observations[0].ExtraJSON == "" {
		t.Fatalf("expected extra_json to be present in gping history")
	}
	rendered := RenderHistory(history, true)
	if !strings.Contains(rendered, "gping history for 127.0.0.1") {
		t.Fatalf("unexpected history rendering: %s", rendered)
	}
	if !strings.Contains(rendered, "extra_json:") {
		t.Fatalf("expected verbose history rendering to include extra_json: %s", rendered)
	}
}

func TestRunHTTPPostSendsBodyAndQuery(t *testing.T) {
	var (
		gotMethod string
		gotQuery  string
		gotBody   string
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Server", "api-gateway/2.0")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := Run(context.Background(), Options{
		Commandline:        "goscan gping --url https://127.0.0.1/submit --method http-post",
		URL:                server.URL,
		Route:              "app",
		Method:             "http-post",
		Path:               "/submit?mode=test",
		Body:               `{"name":"demo"}`,
		Headers:            map[string]string{"Content-Type": "application/json"},
		InsecureSkipVerify: true,
		Timeout:            3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected HTTP method: got %q want POST", gotMethod)
	}
	if gotQuery != "mode=test" {
		t.Fatalf("unexpected query string: got %q want mode=test", gotQuery)
	}
	if gotBody != `{"name":"demo"}` {
		t.Fatalf("unexpected request body: got %q", gotBody)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	if result.Reports[0].RawStatus != "201 Created" {
		t.Fatalf("unexpected http-post status: got %q want 201 Created", result.Reports[0].RawStatus)
	}
	if !hasClaim(result.Reports[0], "http", "status_code", "201") {
		t.Fatalf("expected http.status_code claim, got %+v", result.Reports[0].Claims)
	}
}

func hasClaim(report ExecutionReport, namespace string, name string, value string) bool {
	for _, claim := range report.Claims {
		if claim.Namespace == namespace && claim.Name == name && claim.ValueText == value {
			return true
		}
	}
	return false
}

func mustParsePort(t *testing.T, value string) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
		t.Fatalf("fmt.Sscanf returned error: %v", err)
	}
	return port
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
