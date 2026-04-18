package core

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RunTuning struct {
	TimingLevel          int     `json:"timing_level" yaml:"timing_level"`
	MinPacketSendRatePPS float32 `json:"min_packet_send_rate_pps,omitempty" yaml:"min_packet_send_rate_pps,omitempty"`
	MaxPacketSendRatePPS float32 `json:"max_packet_send_rate_pps,omitempty" yaml:"max_packet_send_rate_pps,omitempty"`
	MinParallelism       int     `json:"min_parallelism,omitempty" yaml:"min_parallelism,omitempty"`
	MaxParallelism       int     `json:"max_parallelism,omitempty" yaml:"max_parallelism,omitempty"`
	MaxRetries           int     `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
	MaxRTTTimeoutMS      int     `json:"max_rtt_timeout_ms,omitempty" yaml:"max_rtt_timeout_ms,omitempty"`
	HostTimeoutMS        int     `json:"host_timeout_ms,omitempty" yaml:"host_timeout_ms,omitempty"`
	RandomizeHosts       bool    `json:"randomize_hosts,omitempty" yaml:"randomize_hosts,omitempty"`
	TTL                  int     `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	Fragment             bool    `json:"fragment,omitempty" yaml:"fragment,omitempty"`
	BadChecksum          bool    `json:"bad_checksum,omitempty" yaml:"bad_checksum,omitempty"`
	SourcePort           int     `json:"source_port,omitempty" yaml:"source_port,omitempty"`
}

type PortraitPerformance struct {
	Runtime  PortraitRuntime  `json:"runtime" yaml:"runtime"`
	Counters PortraitCounters `json:"counters" yaml:"counters"`
	Rates    PortraitRates    `json:"rates" yaml:"rates"`
	Tuning   RunTuning        `json:"tuning" yaml:"tuning"`
	Findings PortraitFindings `json:"findings" yaml:"findings"`
	Pcap     *PortraitPcap    `json:"pcap,omitempty" yaml:"pcap,omitempty"`
}

type PortraitRuntime struct {
	StartedAt      string  `json:"started_at" yaml:"started_at"`
	FinishedAt     string  `json:"finished_at" yaml:"finished_at"`
	ElapsedSeconds float64 `json:"elapsed_seconds" yaml:"elapsed_seconds"`
	ElapsedHuman   string  `json:"elapsed_human" yaml:"elapsed_human"`
	SmoothedRTOMS  int64   `json:"smoothed_rto_ms,omitempty" yaml:"smoothed_rto_ms,omitempty"`
}

type PortraitCounters struct {
	TargetCount        int64 `json:"target_count" yaml:"target_count"`
	PlannedTasks       int64 `json:"planned_tasks" yaml:"planned_tasks"`
	CompletedTasks     int64 `json:"completed_tasks" yaml:"completed_tasks"`
	PendingTasks       int64 `json:"pending_tasks" yaml:"pending_tasks"`
	PacketsSent        int64 `json:"packets_sent" yaml:"packets_sent"`
	PacketsMatched     int64 `json:"packets_matched" yaml:"packets_matched"`
	DispatchDrops      int64 `json:"dispatch_drops" yaml:"dispatch_drops"`
	FilteredTasks      int64 `json:"filtered_tasks" yaml:"filtered_tasks"`
	AliveHosts         int64 `json:"alive_hosts" yaml:"alive_hosts"`
	OpenPorts          int64 `json:"open_ports" yaml:"open_ports"`
	HostsWithFindings  int64 `json:"hosts_with_findings" yaml:"hosts_with_findings"`
	PortsWithFindings  int64 `json:"ports_with_findings" yaml:"ports_with_findings"`
	ServicesIdentified int64 `json:"services_identified" yaml:"services_identified"`
	FactsTotal         int64 `json:"facts_total" yaml:"facts_total"`
}

type PortraitRates struct {
	CompletionPercent    float64 `json:"completion_percent" yaml:"completion_percent"`
	AveragePPS           float64 `json:"average_pps" yaml:"average_pps"`
	MatchedPPS           float64 `json:"matched_pps" yaml:"matched_pps"`
	MatchPercent         float64 `json:"match_percent" yaml:"match_percent"`
	EffectiveSendRatePPS float64 `json:"effective_send_rate_pps,omitempty" yaml:"effective_send_rate_pps,omitempty"`
}

type PortraitFindings struct {
	FactsByState    map[string]int64 `json:"facts_by_state,omitempty" yaml:"facts_by_state,omitempty"`
	FactsByMethod   map[string]int64 `json:"facts_by_method,omitempty" yaml:"facts_by_method,omitempty"`
	PortsByProtocol map[string]int64 `json:"ports_by_protocol,omitempty" yaml:"ports_by_protocol,omitempty"`
}

type PortraitPcap struct {
	PacketsReceived  int64 `json:"packets_received" yaml:"packets_received"`
	PacketsDropped   int64 `json:"packets_dropped" yaml:"packets_dropped"`
	PacketsIfDropped int64 `json:"packets_if_dropped" yaml:"packets_if_dropped"`
}

type portraitAggregationStats struct {
	HostsWithFindings  int64
	PortsWithFindings  int64
	ServicesIdentified int64
	FactsTotal         int64
	FactsByState       map[string]int64
	FactsByMethod      map[string]int64
	PortsByProtocol    map[string]int64
}

type finalEngineStats struct {
	EffectiveSendRatePPS float64
	SmoothedRTOMS        int64
	PacketsReceived      int64
	PacketsDropped       int64
	PacketsIfDropped     int64
}

var (
	finalEngineStatsMu sync.RWMutex
	finalEngineStatsV  finalEngineStats
)

func resetFinalEngineStats() {
	finalEngineStatsMu.Lock()
	finalEngineStatsV = finalEngineStats{}
	finalEngineStatsMu.Unlock()
}

func storeFinalEngineStats(stats finalEngineStats) {
	finalEngineStatsMu.Lock()
	finalEngineStatsV = stats
	finalEngineStatsMu.Unlock()
}

func loadFinalEngineStats() finalEngineStats {
	finalEngineStatsMu.RLock()
	defer finalEngineStatsMu.RUnlock()
	return finalEngineStatsV
}

func buildPortraitPerformance(metadata RunMetadata, finishedAt time.Time, agg portraitAggregationStats) PortraitPerformance {
	startedAt := GlobalMetrics.StartTime
	if startedAt.IsZero() {
		startedAt = finishedAt
	}
	elapsed := finishedAt.Sub(startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	elapsedSeconds := elapsed.Seconds()
	if elapsedSeconds <= 0 {
		elapsedSeconds = 1
	}

	totalTasks := atomic.LoadInt64(&GlobalMetrics.TotalTasks)
	completedTasks := atomic.LoadInt64(&GlobalMetrics.TasksDone)
	pendingTasks := totalTasks - completedTasks
	if pendingTasks < 0 {
		pendingTasks = 0
	}
	packetsSent := atomic.LoadInt64(&GlobalMetrics.PacketsSent)
	packetsMatched := atomic.LoadInt64(&GlobalMetrics.PacketsMatched)
	dispatchDrops := atomic.LoadInt64(&GlobalMetrics.DispatchDrops)
	filteredTasks := atomic.LoadInt64(&GlobalMetrics.Filtered)
	aliveHosts := atomic.LoadInt64(&GlobalMetrics.AliveHosts)
	openPorts := atomic.LoadInt64(&GlobalMetrics.OpenPorts)

	completionPercent := 100.0
	if totalTasks > 0 {
		completionPercent = float64(completedTasks) / float64(totalTasks) * 100
	}
	matchPercent := 0.0
	if packetsSent > 0 {
		matchPercent = float64(packetsMatched) / float64(packetsSent) * 100
	}

	engineStats := loadFinalEngineStats()
	performance := PortraitPerformance{
		Runtime: PortraitRuntime{
			StartedAt:      startedAt.Format(time.RFC3339),
			FinishedAt:     finishedAt.Format(time.RFC3339),
			ElapsedSeconds: elapsed.Seconds(),
			ElapsedHuman:   elapsed.Round(time.Millisecond).String(),
			SmoothedRTOMS:  engineStats.SmoothedRTOMS,
		},
		Counters: PortraitCounters{
			TargetCount:        int64(len(metadata.Targets)),
			PlannedTasks:       totalTasks,
			CompletedTasks:     completedTasks,
			PendingTasks:       pendingTasks,
			PacketsSent:        packetsSent,
			PacketsMatched:     packetsMatched,
			DispatchDrops:      dispatchDrops,
			FilteredTasks:      filteredTasks,
			AliveHosts:         aliveHosts,
			OpenPorts:          openPorts,
			HostsWithFindings:  agg.HostsWithFindings,
			PortsWithFindings:  agg.PortsWithFindings,
			ServicesIdentified: agg.ServicesIdentified,
			FactsTotal:         agg.FactsTotal,
		},
		Rates: PortraitRates{
			CompletionPercent:    completionPercent,
			AveragePPS:           float64(packetsSent) / elapsedSeconds,
			MatchedPPS:           float64(packetsMatched) / elapsedSeconds,
			MatchPercent:         matchPercent,
			EffectiveSendRatePPS: engineStats.EffectiveSendRatePPS,
		},
		Tuning: metadata.Tuning,
		Findings: PortraitFindings{
			FactsByState:    cloneInt64Map(agg.FactsByState),
			FactsByMethod:   cloneInt64Map(agg.FactsByMethod),
			PortsByProtocol: cloneInt64Map(agg.PortsByProtocol),
		},
	}

	if engineStats.PacketsReceived > 0 || engineStats.PacketsDropped > 0 || engineStats.PacketsIfDropped > 0 {
		performance.Pcap = &PortraitPcap{
			PacketsReceived:  engineStats.PacketsReceived,
			PacketsDropped:   engineStats.PacketsDropped,
			PacketsIfDropped: engineStats.PacketsIfDropped,
		}
	}

	return performance
}

func renderPortraitPerformanceSummary(perf PortraitPerformance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n================ Going_Scan Performance ================\n")
	fmt.Fprintf(&b, "Runtime: %s (%0.2fs)\n", perf.Runtime.ElapsedHuman, perf.Runtime.ElapsedSeconds)
	fmt.Fprintf(&b, "Tasks: %d planned | %d completed | %d pending | %.2f%% done\n",
		perf.Counters.PlannedTasks, perf.Counters.CompletedTasks, perf.Counters.PendingTasks, perf.Rates.CompletionPercent)
	fmt.Fprintf(&b, "Packets: %d sent | %d matched | %d drops | %d filtered\n",
		perf.Counters.PacketsSent, perf.Counters.PacketsMatched, perf.Counters.DispatchDrops, perf.Counters.FilteredTasks)
	fmt.Fprintf(&b, "Discovery: %d alive hosts | %d open ports | %d hosts with findings | %d services identified\n",
		perf.Counters.AliveHosts, perf.Counters.OpenPorts, perf.Counters.HostsWithFindings, perf.Counters.ServicesIdentified)
	fmt.Fprintf(&b, "Throughput: %.0f avg pps | %.0f matched pps | %.2f%% match\n",
		perf.Rates.AveragePPS, perf.Rates.MatchedPPS, perf.Rates.MatchPercent)
	if perf.Rates.EffectiveSendRatePPS > 0 {
		fmt.Fprintf(&b, "Send Rate: %.0f effective pps", perf.Rates.EffectiveSendRatePPS)
		if perf.Tuning.MaxPacketSendRatePPS > 0 || perf.Tuning.MinPacketSendRatePPS > 0 {
			fmt.Fprintf(&b, " (configured min=%.0f max=%.0f)", perf.Tuning.MinPacketSendRatePPS, perf.Tuning.MaxPacketSendRatePPS)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Tuning: T%d | parallelism=%d-%d | retries=%d | max-rtt=%dms\n",
		perf.Tuning.TimingLevel,
		perf.Tuning.MinParallelism,
		perf.Tuning.MaxParallelism,
		perf.Tuning.MaxRetries,
		perf.Tuning.MaxRTTTimeoutMS,
	)
	if perf.Runtime.SmoothedRTOMS > 0 {
		fmt.Fprintf(&b, "RTO: %d ms smoothed\n", perf.Runtime.SmoothedRTOMS)
	}
	if perf.Pcap != nil {
		fmt.Fprintf(&b, "Pcap: recv=%d drop=%d ifdrop=%d\n",
			perf.Pcap.PacketsReceived, perf.Pcap.PacketsDropped, perf.Pcap.PacketsIfDropped)
	}
	fmt.Fprintf(&b, "Facts: %d total | ports=%d | protocols=%s\n",
		perf.Counters.FactsTotal,
		perf.Counters.PortsWithFindings,
		renderCompactInt64Map(perf.Findings.PortsByProtocol),
	)
	fmt.Fprintf(&b, "By State: %s\n", renderCompactInt64Map(perf.Findings.FactsByState))
	fmt.Fprintf(&b, "By Method: %s\n", renderCompactInt64Map(perf.Findings.FactsByMethod))
	fmt.Fprintf(&b, "========================================================\n")
	return b.String()
}

func cloneInt64Map(src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]int64, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func renderCompactInt64Map(items map[string]int64) string {
	if len(items) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, items[key]))
	}
	return strings.Join(parts, " ")
}

func sortStrings(items []string) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j] < items[i] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}
