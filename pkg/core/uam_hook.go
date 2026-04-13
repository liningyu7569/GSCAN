package core

import (
	"Going_Scan/internal/uam/service"
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/util"
	"context"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
)

const uamQueueSize = 65536

type uamEventKind string

const (
	uamEventL4Raw     uamEventKind = "l4_raw"
	uamEventL7Service uamEventKind = "l7_service"
	uamEventDiscovery uamEventKind = "discovery"
)

type uamEvent struct {
	kind      uamEventKind
	result    *service.ScanResult
	discovery *service.GSDiscoveryResult
}

var (
	uamHookMu       sync.Mutex
	uamGSIngester   *service.GSIngester
	uamHookDisabled bool
	uamEventQueue   chan uamEvent
	uamWorkerWG     sync.WaitGroup
)

func InitUAMHook() {
	initSQLiteHook()
}

func initSQLiteHook() {
	uamHookMu.Lock()
	defer uamHookMu.Unlock()

	if uamGSIngester != nil || uamHookDisabled {
		return
	}

	dbPath := strings.TrimSpace(conf.GlobalOps.UAMDBPath)
	if dbPath == "" {
		uamHookDisabled = true
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	metadata := GetRunMetadata()
	ingester, err := service.NewGSIngester(ctx, dbPath, service.RunMetadata{
		Command:      metadata.Command,
		Targets:      metadata.Targets,
		Ports:        metadata.Ports,
		Profiles:     metadata.Profiles,
		ServiceScan:  metadata.ServiceScan,
		OutputFile:   metadata.OutputFile,
		OutputFormat: metadata.OutputFormat,
	})
	if err != nil {
		fmt.Printf("[UAM] 初始化失败，已跳过 SQLite 持久化: %v\n", err)
		uamHookDisabled = true
		return
	}

	uamGSIngester = ingester
	uamEventQueue = make(chan uamEvent, uamQueueSize)
	uamWorkerWG.Add(1)
	go runUAMWorker(ingester, uamEventQueue)

	fmt.Printf("[UAM] 已接入 SQLite 资产契约层: %s\n", dbPath)
}

func runUAMWorker(ingester *service.GSIngester, events <-chan uamEvent) {
	defer uamWorkerWG.Done()

	for evt := range events {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err error
		switch evt.kind {
		case uamEventDiscovery:
			if evt.discovery != nil {
				err = ingester.IngestDiscovery(ctx, *evt.discovery)
			}
		case uamEventL4Raw:
			if evt.result != nil {
				err = ingester.IngestResult(ctx, *evt.result)
			}
		case uamEventL7Service:
			if evt.result != nil {
				err = ingester.IngestServiceResult(ctx, *evt.result)
			}
		}
		cancel()

		if err != nil {
			fmt.Printf("[UAM] 写入失败，已跳过本条事件: %v\n", err)
		}
	}
}

func enqueueUAMEvent(evt uamEvent) {
	uamHookMu.Lock()
	queue := uamEventQueue
	disabled := uamHookDisabled
	uamHookMu.Unlock()

	if disabled || queue == nil {
		return
	}

	queue <- evt
}

func recordUAMRawL4Result(task EmissionTask, state uint8) {
	if state == ScanStateUnknown || task.IsHostDiscovery {
		return
	}

	enqueueUAMEvent(uamEvent{
		kind: uamEventL4Raw,
		result: &service.ScanResult{
			IP:       uint32ToIPString(task.TargetIP),
			Port:     int(task.TargetPort),
			Protocol: strings.ToLower(protocolToStr(task.Protocol)),
			Method:   gsMethodForTask(task),
			State:    scanStateToString(state),
		},
	})
}

func recordUAMHostDiscovery(task EmissionTask) {
	if !task.IsHostDiscovery {
		return
	}

	enqueueUAMEvent(uamEvent{
		kind: uamEventDiscovery,
		discovery: &service.GSDiscoveryResult{
			IP:       uint32ToIPString(task.TargetIP),
			Method:   gsMethodForTask(task),
			Status:   "alive",
			Protocol: strings.ToLower(protocolToStr(task.Protocol)),
		},
	})
}

func saveToSQLiteHook(result ScanResult, _ string) {
	if !hasUAMServicePayload(result) {
		return
	}

	enqueueUAMEvent(uamEvent{
		kind: uamEventL7Service,
		result: &service.ScanResult{
			IP:       result.IPStr,
			Port:     int(result.Port),
			Protocol: strings.ToLower(protocolToStr(result.Protocol)),
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
		},
	})
}

func closeSQLiteHook() {
	uamHookMu.Lock()
	ingester := uamGSIngester
	queue := uamEventQueue
	uamGSIngester = nil
	uamEventQueue = nil
	uamHookMu.Unlock()

	if queue != nil {
		close(queue)
		uamWorkerWG.Wait()
	}

	if ingester == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := ingester.Close(ctx); err != nil {
		fmt.Printf("[UAM] 结束 Run 时出现错误: %v\n", err)
	}
}

func hasUAMServicePayload(result ScanResult) bool {
	if result.Product != "" || result.Version != "" || result.Info != "" || result.Hostname != "" || result.OS != "" || result.Device != "" || result.Banner != "" || len(result.CPEs) > 0 {
		return true
	}
	return result.Service != "" && result.Service != "unknown"
}

func gsMethodForTask(task EmissionTask) string {
	if task.IsHostDiscovery {
		switch task.Protocol {
		case syscall.IPPROTO_ICMP:
			return "icmp-echo"
		case syscall.IPPROTO_TCP:
			return "tcp-syn-ping"
		case syscall.IPPROTO_UDP:
			return "udp-ping"
		default:
			return "host-discovery"
		}
	}
	return scanKindToString(task.ScanKind)
}

func uint32ToIPString(ip uint32) string {
	return util.Uint32ToIP(ip).String()
}
