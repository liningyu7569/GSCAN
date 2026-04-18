package core

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ScanFact struct {
	Method   string   `json:"method" yaml:"method"`
	State    string   `json:"state" yaml:"state"`
	Service  string   `json:"service,omitempty" yaml:"service,omitempty"`
	Product  string   `json:"product,omitempty" yaml:"product,omitempty"`
	Version  string   `json:"version,omitempty" yaml:"version,omitempty"`
	Info     string   `json:"info,omitempty" yaml:"info,omitempty"`
	Hostname string   `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	OS       string   `json:"os,omitempty" yaml:"os,omitempty"`
	Device   string   `json:"device,omitempty" yaml:"device,omitempty"`
	CPEs     []string `json:"cpes,omitempty" yaml:"cpes,omitempty"`
	Banner   string   `json:"banner,omitempty" yaml:"banner,omitempty"`
}

type PortPortrait struct {
	Port         uint16     `json:"port" yaml:"port"`
	Protocol     string     `json:"protocol" yaml:"protocol"`
	SummaryState string     `json:"summary_state" yaml:"summary_state"`
	Service      string     `json:"service,omitempty" yaml:"service,omitempty"`
	Product      string     `json:"product,omitempty" yaml:"product,omitempty"`
	Version      string     `json:"version,omitempty" yaml:"version,omitempty"`
	Info         string     `json:"info,omitempty" yaml:"info,omitempty"`
	Hostname     string     `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	OS           string     `json:"os,omitempty" yaml:"os,omitempty"`
	Device       string     `json:"device,omitempty" yaml:"device,omitempty"`
	CPEs         []string   `json:"cpes,omitempty" yaml:"cpes,omitempty"`
	Banner       string     `json:"banner,omitempty" yaml:"banner,omitempty"`
	Facts        []ScanFact `json:"facts" yaml:"facts"`
}

type HostPortrait struct {
	IP    string         `json:"ip" yaml:"ip"`
	Ports []PortPortrait `json:"ports" yaml:"ports"`
}

type PortraitReport struct {
	Metadata    PortraitMetadata    `json:"metadata" yaml:"metadata"`
	Performance PortraitPerformance `json:"performance" yaml:"performance"`
	Hosts       []HostPortrait      `json:"hosts" yaml:"hosts"`
}

type PortraitMetadata struct {
	Command       string   `json:"command" yaml:"command"`
	Targets       []string `json:"targets" yaml:"targets"`
	Profiles      []string `json:"profiles" yaml:"profiles"`
	ResolvedPorts []int    `json:"resolved_ports" yaml:"resolved_ports"`
	ServiceScan   bool     `json:"service_scan" yaml:"service_scan"`
	OutputFormat  string   `json:"output_format,omitempty" yaml:"output_format,omitempty"`
	GeneratedAt   string   `json:"generated_at" yaml:"generated_at"`
}

type PortraitAggregator struct {
	entries map[string]*portraitEntry
}

type portraitEntry struct {
	IP       string
	Port     uint16
	Protocol string
	Facts    map[string]ScanFact
	Service  string
	Product  string
	Version  string
	Info     string
	Hostname string
	OS       string
	Device   string
	CPEs     []string
	Banner   string
}

func NewPortraitAggregator() *PortraitAggregator {
	return &PortraitAggregator{
		entries: make(map[string]*portraitEntry),
	}
}

func (a *PortraitAggregator) Add(result ScanResult) {
	if a == nil {
		return
	}

	key := fmt.Sprintf("%s|%s|%05d", result.IPStr, protocolToStr(result.Protocol), result.Port)
	entry, ok := a.entries[key]
	if !ok {
		entry = &portraitEntry{
			IP:       result.IPStr,
			Port:     result.Port,
			Protocol: protocolToStr(result.Protocol),
			Facts:    make(map[string]ScanFact),
		}
		a.entries[key] = entry
	}

	entry.Facts[result.Method] = ScanFact{
		Method:   result.Method,
		State:    result.State,
		Service:  result.Service,
		Product:  result.Product,
		Version:  result.Version,
		Info:     result.Info,
		Hostname: result.Hostname,
		OS:       result.OS,
		Device:   result.Device,
		CPEs:     append([]string(nil), result.CPEs...),
		Banner:   result.Banner,
	}

	if result.Service != "" || result.Banner != "" {
		entry.Service = result.Service
		entry.Product = result.Product
		entry.Version = result.Version
		entry.Info = result.Info
		entry.Hostname = result.Hostname
		entry.OS = result.OS
		entry.Device = result.Device
		entry.CPEs = append([]string(nil), result.CPEs...)
	}
	if result.Banner != "" {
		entry.Banner = result.Banner
	}
}

func (a *PortraitAggregator) Build(metadata RunMetadata, generatedAt time.Time) PortraitReport {
	hostsMap := make(map[string][]PortPortrait)
	stats := portraitAggregationStats{
		FactsByState:    make(map[string]int64),
		FactsByMethod:   make(map[string]int64),
		PortsByProtocol: make(map[string]int64),
	}
	for _, entry := range a.entries {
		facts := make([]ScanFact, 0, len(entry.Facts))
		for _, fact := range entry.Facts {
			facts = append(facts, fact)
			stats.FactsTotal++
			stats.FactsByState[fact.State]++
			stats.FactsByMethod[fact.Method]++
		}
		sort.Slice(facts, func(i, j int) bool {
			return methodOrder(facts[i].Method) < methodOrder(facts[j].Method)
		})

		stats.PortsByProtocol[entry.Protocol]++
		stats.PortsWithFindings++
		if entry.Service != "" && entry.Service != "unknown" && entry.Service != "unreachable" {
			stats.ServicesIdentified++
		}
		hostsMap[entry.IP] = append(hostsMap[entry.IP], PortPortrait{
			Port:         entry.Port,
			Protocol:     entry.Protocol,
			SummaryState: summarizeFacts(facts),
			Service:      entry.Service,
			Product:      entry.Product,
			Version:      entry.Version,
			Info:         entry.Info,
			Hostname:     entry.Hostname,
			OS:           entry.OS,
			Device:       entry.Device,
			CPEs:         append([]string(nil), entry.CPEs...),
			Banner:       entry.Banner,
			Facts:        facts,
		})
	}

	hostIPs := make([]string, 0, len(hostsMap))
	for ip := range hostsMap {
		hostIPs = append(hostIPs, ip)
	}
	sort.Strings(hostIPs)

	hosts := make([]HostPortrait, 0, len(hostIPs))
	for _, ip := range hostIPs {
		ports := hostsMap[ip]
		sort.Slice(ports, func(i, j int) bool {
			if ports[i].Port != ports[j].Port {
				return ports[i].Port < ports[j].Port
			}
			return protocolOrder(ports[i].Protocol) < protocolOrder(ports[j].Protocol)
		})
		hosts = append(hosts, HostPortrait{
			IP:    ip,
			Ports: ports,
		})
	}
	stats.HostsWithFindings = int64(len(hosts))

	return PortraitReport{
		Metadata: PortraitMetadata{
			Command:       metadata.Command,
			Targets:       append([]string(nil), metadata.Targets...),
			Profiles:      append([]string(nil), metadata.Profiles...),
			ResolvedPorts: append([]int(nil), metadata.Ports...),
			ServiceScan:   metadata.ServiceScan,
			OutputFormat:  metadata.OutputFormat,
			GeneratedAt:   generatedAt.Format(time.RFC3339),
		},
		Performance: buildPortraitPerformance(metadata, generatedAt, stats),
		Hosts:       hosts,
	}
}

func WritePortraitReport(path string, format string, report PortraitReport) error {
	var (
		data []byte
		err  error
	)

	switch format {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(report)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
	if err != nil {
		return err
	}

	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	return os.WriteFile(path, data, 0666)
}

func summarizeFacts(facts []ScanFact) string {
	hasOpenProof := false
	hasLikelyOpen := false
	hasClosed := false
	hasFiltered := false
	hasUnfiltered := false

	for _, fact := range facts {
		switch fact.Method {
		case "tcp-syn", "udp":
			if fact.State == "open" {
				hasOpenProof = true
			}
		case "tcp-window":
			if fact.State == "open" {
				hasLikelyOpen = true
			}
		}

		switch fact.State {
		case "closed":
			hasClosed = true
		case "filtered":
			hasFiltered = true
		case "unfiltered":
			hasUnfiltered = true
		}
	}

	switch {
	case hasOpenProof:
		return "open"
	case hasLikelyOpen:
		return "likely-open"
	case hasClosed:
		return "closed"
	case hasFiltered && hasUnfiltered:
		return "mixed"
	case hasUnfiltered:
		return "unfiltered"
	case hasFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

func methodOrder(method string) int {
	switch method {
	case "tcp-syn":
		return 0
	case "tcp-ack":
		return 1
	case "tcp-window":
		return 2
	case "udp":
		return 3
	default:
		return 99
	}
}

func protocolOrder(protocol string) int {
	switch strings.ToUpper(protocol) {
	case "TCP":
		return 0
	case "UDP":
		return 1
	case "ICMP":
		return 2
	default:
		return 99
	}
}
