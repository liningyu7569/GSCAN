package core

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPortraitAggregatorBuildsSummaryFromFacts(t *testing.T) {
	aggregator := NewPortraitAggregator()
	aggregator.Add(ScanResult{
		IP:       0xC0A80101,
		IPStr:    "192.168.1.1",
		Port:     80,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-ack",
		State:    "unfiltered",
	})
	aggregator.Add(ScanResult{
		IP:       0xC0A80101,
		IPStr:    "192.168.1.1",
		Port:     80,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-window",
		State:    "open",
	})
	aggregator.Add(ScanResult{
		IP:       0xC0A80101,
		IPStr:    "192.168.1.1",
		Port:     80,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-syn",
		State:    "open",
		Service:  "http",
		Product:  "Apache httpd",
		Version:  "2.4.58",
		Info:     "Ubuntu",
		Hostname: "edge-1",
		OS:       "Linux",
		Device:   "web server",
		CPEs:     []string{"a:apache:http_server:2.4.58"},
		Banner:   "Apache",
	})

	report := aggregator.Build(RunMetadata{
		Command:     "goscan scan 192.168.1.1 --syn --ack --window",
		Targets:     []string{"192.168.1.1"},
		Ports:       []int{80},
		Profiles:    []string{"tcp-syn", "tcp-ack", "tcp-window"},
		ServiceScan: true,
	}, time.Unix(0, 0))

	if len(report.Hosts) != 1 || len(report.Hosts[0].Ports) != 1 {
		t.Fatalf("unexpected report shape: %+v", report)
	}

	port := report.Hosts[0].Ports[0]
	if port.SummaryState != "open" {
		t.Fatalf("unexpected summary state: got %q want open", port.SummaryState)
	}
	if port.Service != "http" || port.Banner != "Apache" {
		t.Fatalf("unexpected service/banner: %+v", port)
	}
	if port.Product != "Apache httpd" || port.Version != "2.4.58" || port.Info != "Ubuntu" {
		t.Fatalf("unexpected fingerprint summary: %+v", port)
	}
	if port.Hostname != "edge-1" || port.OS != "Linux" || port.Device != "web server" {
		t.Fatalf("unexpected host/device summary: %+v", port)
	}
	if len(port.CPEs) != 1 || port.CPEs[0] != "a:apache:http_server:2.4.58" {
		t.Fatalf("unexpected cpes: %+v", port.CPEs)
	}
	if len(port.Facts) != 3 {
		t.Fatalf("unexpected fact count: got %d want 3", len(port.Facts))
	}
	if port.Facts[0].Method != "tcp-syn" && port.Facts[1].Method != "tcp-syn" && port.Facts[2].Method != "tcp-syn" {
		t.Fatalf("expected tcp-syn fact to be present: %+v", port.Facts)
	}
}

func TestSummarizeFacts(t *testing.T) {
	tests := []struct {
		name  string
		facts []ScanFact
		want  string
	}{
		{
			name:  "unfiltered only",
			facts: []ScanFact{{Method: "tcp-ack", State: "unfiltered"}},
			want:  "unfiltered",
		},
		{
			name:  "window heuristic",
			facts: []ScanFact{{Method: "tcp-window", State: "open"}},
			want:  "likely-open",
		},
		{
			name:  "filtered and unfiltered",
			facts: []ScanFact{{Method: "tcp-ack", State: "unfiltered"}, {Method: "tcp-window", State: "filtered"}},
			want:  "mixed",
		},
		{
			name:  "udp closed",
			facts: []ScanFact{{Method: "udp", State: "closed"}},
			want:  "closed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeFacts(tc.facts); got != tc.want {
				t.Fatalf("unexpected summary: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestWritePortraitReportSupportsJSONAndYAML(t *testing.T) {
	report := PortraitReport{
		Metadata: PortraitMetadata{
			Command:       "goscan scan 127.0.0.1",
			Targets:       []string{"127.0.0.1"},
			Profiles:      []string{"tcp-syn"},
			ResolvedPorts: []int{80},
			ServiceScan:   false,
			OutputFormat:  "json",
			GeneratedAt:   "2026-04-11T00:00:00Z",
		},
		Hosts: []HostPortrait{{
			IP: "127.0.0.1",
			Ports: []PortPortrait{{
				Port:         80,
				Protocol:     "TCP",
				SummaryState: "open",
				Facts: []ScanFact{{
					Method: "tcp-syn",
					State:  "open",
				}},
			}},
		}},
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	if err := WritePortraitReport(jsonPath, "json", report); err != nil {
		t.Fatalf("WritePortraitReport json returned error: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(jsonData), "\"summary_state\": \"open\"") {
		t.Fatalf("unexpected json output: %s", string(jsonData))
	}

	yamlPath := filepath.Join(dir, "report.yaml")
	report.Metadata.OutputFormat = "yaml"
	if err := WritePortraitReport(yamlPath, "yaml", report); err != nil {
		t.Fatalf("WritePortraitReport yaml returned error: %v", err)
	}
	yamlData, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(yamlData), "summary_state: open") {
		t.Fatalf("unexpected yaml output: %s", string(yamlData))
	}
}
