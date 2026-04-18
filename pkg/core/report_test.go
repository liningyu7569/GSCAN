package core

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		Performance: PortraitPerformance{
			Runtime: PortraitRuntime{
				StartedAt:      "2026-04-11T00:00:00Z",
				FinishedAt:     "2026-04-11T00:00:02Z",
				ElapsedSeconds: 2,
				ElapsedHuman:   "2s",
			},
			Counters: PortraitCounters{
				PlannedTasks:   10,
				CompletedTasks: 10,
				PacketsSent:    20,
				AliveHosts:     1,
				OpenPorts:      1,
			},
			Rates: PortraitRates{
				AveragePPS:        10,
				CompletionPercent: 100,
			},
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
	if !strings.Contains(string(jsonData), "\"performance\"") || !strings.Contains(string(jsonData), "\"alive_hosts\": 1") {
		t.Fatalf("expected performance metrics in json output: %s", string(jsonData))
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
	if !strings.Contains(string(yamlData), "performance:") || !strings.Contains(string(yamlData), "alive_hosts: 1") {
		t.Fatalf("expected performance metrics in yaml output: %s", string(yamlData))
	}
}

func TestPortraitAggregatorBuildIncludesPerformanceMetrics(t *testing.T) {
	savedMetrics := GlobalMetrics
	savedFinal := loadFinalEngineStats()
	defer func() {
		GlobalMetrics = savedMetrics
		storeFinalEngineStats(savedFinal)
	}()

	GlobalMetrics = &ScanMetrics{StartTime: time.Unix(0, 0)}
	atomic.StoreInt64(&GlobalMetrics.TotalTasks, 20)
	atomic.StoreInt64(&GlobalMetrics.TasksDone, 20)
	atomic.StoreInt64(&GlobalMetrics.PacketsSent, 40)
	atomic.StoreInt64(&GlobalMetrics.PacketsMatched, 25)
	atomic.StoreInt64(&GlobalMetrics.DispatchDrops, 2)
	atomic.StoreInt64(&GlobalMetrics.Filtered, 5)
	atomic.StoreInt64(&GlobalMetrics.OpenPorts, 2)
	atomic.StoreInt64(&GlobalMetrics.AliveHosts, 1)
	storeFinalEngineStats(finalEngineStats{
		EffectiveSendRatePPS: 3000,
		SmoothedRTOMS:        180,
		PacketsReceived:      88,
		PacketsDropped:       3,
		PacketsIfDropped:     1,
	})

	aggregator := NewPortraitAggregator()
	aggregator.Add(ScanResult{
		IPStr:    "192.168.1.10",
		Port:     80,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-syn",
		State:    "open",
		Service:  "http",
	})
	aggregator.Add(ScanResult{
		IPStr:    "192.168.1.10",
		Port:     443,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-syn",
		State:    "open",
		Service:  "https",
	})
	aggregator.Add(ScanResult{
		IPStr:    "192.168.1.10",
		Port:     443,
		Protocol: syscall.IPPROTO_TCP,
		Method:   "tcp-window",
		State:    "open",
	})

	report := aggregator.Build(RunMetadata{
		Command:     "goscan scan 192.168.1.10 -p 80,443 --syn -V",
		Targets:     []string{"192.168.1.10"},
		Ports:       []int{80, 443},
		Profiles:    []string{"tcp-syn"},
		ServiceScan: true,
		Tuning: RunTuning{
			TimingLevel:     3,
			MaxRetries:      1,
			MaxRTTTimeoutMS: 1000,
		},
	}, time.Unix(2, 0))

	if report.Performance.Counters.AliveHosts != 1 || report.Performance.Counters.OpenPorts != 2 {
		t.Fatalf("unexpected performance counters: %+v", report.Performance.Counters)
	}
	if report.Performance.Counters.ServicesIdentified != 2 {
		t.Fatalf("unexpected services identified count: %+v", report.Performance.Counters)
	}
	if report.Performance.Findings.FactsByMethod["tcp-syn"] != 2 || report.Performance.Findings.FactsByMethod["tcp-window"] != 1 {
		t.Fatalf("unexpected facts by method: %+v", report.Performance.Findings.FactsByMethod)
	}
	if report.Performance.Pcap == nil || report.Performance.Pcap.PacketsReceived != 88 {
		t.Fatalf("unexpected pcap stats: %+v", report.Performance.Pcap)
	}
	if report.Performance.Rates.AveragePPS <= 0 || report.Performance.Runtime.SmoothedRTOMS != 180 {
		t.Fatalf("unexpected runtime/rates: %+v %+v", report.Performance.Runtime, report.Performance.Rates)
	}
}
