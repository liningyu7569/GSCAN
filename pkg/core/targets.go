package core

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/queue"
	"Going_Scan/pkg/routing"
	"Going_Scan/pkg/target"
	"Going_Scan/pkg/util"

	"fmt"
	"net"
	"sync"
	"syscall"
)

// TaskGenerator 替代了原来的 HostGroupState
type TaskGenerator struct {
	ipIterator   target.Iterator
	ports        []int
	routeMap     map[string]uint16
	scanProfiles []ScanProfile

	routeResolver func(net.IP) (uint16, error)
}

const shardCount = 256

type hdShard struct {
	sync.Mutex
	m map[uint32]struct{}
}

var (
	hdFilter    [shardCount]*hdShard
	HDReservoir = queue.NewLockFreeRingBuffer[uint32](65536)
)

// 初始化分片
func initHDFilter() {
	for i := 0; i < shardCount; i++ {
		hdFilter[i] = &hdShard{m: make(map[uint32]struct{})}
	}

}

// markAlive 查重并标记，如果是首次发现则返回 true
func markAlive(ip uint32) bool {
	shard := hdFilter[ip%shardCount]
	shard.Lock()
	defer shard.Unlock()

	if _, exists := shard.m[ip]; exists {
		return false // 已经标记过存活，去重
	}
	shard.m[ip] = struct{}{}
	MetricAliveHosts.Add(uint64(ip), 1)
	return true // 首次发现存活
}

// NewTaskGenerator 读取 conf.GlobalOps，固化本次扫描的协议策略
func NewTaskGenerator(iter target.Iterator, ports []int, scanProfiles []ScanProfile) *TaskGenerator {
	if len(scanProfiles) == 0 {
		scanProfiles = DefaultPortScanProfiles()
	}

	gen := &TaskGenerator{
		ipIterator:   iter,
		ports:        ports,
		routeMap:     make(map[string]uint16),
		scanProfiles: append([]ScanProfile(nil), scanProfiles...),
	}

	return gen
}

func (g *TaskGenerator) GenerateBatch() ([]EmissionTask, bool) {
	for {
		// 1. 检查探活开关 (类似 Nmap 的 -Pn)
		if conf.GlobalOps.SkipHostDiscovery {
			// 跳过探活，直接从迭代器拿 IP 生成端口扫描任务
			rawIP := g.ipIterator.Next()
			if rawIP == nil {
				return nil, true
			}

			tasks, err := g.generatePortScanTasks(util.IPToUint32(rawIP))
			if err != nil {
				fmt.Printf("[TaskGenerator] 跳过 %s: %v\n", rawIP.String(), err)
				continue
			}
			return tasks, false
		}

		var aliveIP uint32
		if HDReservoir.Pop(&aliveIP) {
			tasks, err := g.generatePortScanTasks(aliveIP)
			if err != nil {
				fmt.Printf("[TaskGenerator] 跳过 %s: %v\n", util.Uint32ToIP(aliveIP).String(), err)
				continue
			}
			return tasks, false
		}

		rawIP := g.ipIterator.Next()
		if rawIP == nil {
			return nil, true
		}

		tasks, err := g.generateHostDiscoveryTasks(util.IPToUint32(rawIP), rawIP)
		if err != nil {
			fmt.Printf("[TaskGenerator] 跳过 %s: %v\n", rawIP.String(), err)
			continue
		}
		return tasks, false
	}
}

// generatePortScanTasks 生成真正的端口扫描弹药
func (g *TaskGenerator) generatePortScanTasks(targetIPUint32 uint32) ([]EmissionTask, error) {
	rawIP := util.Uint32ToIP(targetIPUint32)
	routeID, err := g.resolveRoute(rawIP)
	if err != nil {
		return nil, err
	}

	tasks := make([]EmissionTask, 0, len(g.ports)*len(g.scanProfiles))
	for _, port := range g.ports {
		for _, profile := range g.scanProfiles {
			tasks = append(tasks, EmissionTask{
				TargetIP:        targetIPUint32,
				TargetPort:      uint16(port),
				RouteID:         routeID,
				Protocol:        profile.Protocol,
				ScanFlags:       profile.ScanFlags,
				ScanKind:        profile.ScanKind,
				IsHostDiscovery: false, // 标记为真实扫描
			})
		}
	}
	return tasks, nil
}

func (g *TaskGenerator) generateHostDiscoveryTasks(targetIPUint32 uint32, rawIP net.IP) ([]EmissionTask, error) {
	routeID, err := g.resolveRoute(rawIP)
	if err != nil {
		return nil, err
	}

	profiles := DefaultHostDiscoveryProfiles()
	tasks := make([]EmissionTask, 0, len(profiles))
	for _, profile := range profiles {
		targetPort := uint16(0)
		if profile.Protocol == syscall.IPPROTO_TCP {
			targetPort = DefaultHostDiscoveryTCPPort
		}

		tasks = append(tasks, EmissionTask{
			TargetIP:        targetIPUint32,
			TargetPort:      targetPort,
			RouteID:         routeID,
			Protocol:        profile.Protocol,
			ScanFlags:       profile.ScanFlags,
			ScanKind:        profile.ScanKind,
			IsHostDiscovery: true,
		})
	}

	return tasks, nil
}

func (g *TaskGenerator) resolveRoute(targetIP net.IP) (uint16, error) {
	if g.routeResolver != nil {
		return g.routeResolver(targetIP)
	}
	return g.resolveAndCacheRoute(targetIP)
}

func (g *TaskGenerator) resolveAndCacheRoute(targetIP net.IP) (uint16, error) {
	// 1. 调用系统路由表查找下一跳
	routeInfo, err := routing.GlobalRouter.RouteTo(targetIP)
	if err != nil {
		return 0, err
	}

	nextHopIP := targetIP
	if routeInfo.Gateway != nil {
		nextHopIP = routeInfo.Gateway
	}
	cacheKey := fmt.Sprintf("%s_%s", routeInfo.Interface.Name, nextHopIP.String())
	if id, exists := g.routeMap[cacheKey]; exists {
		return id, nil
	}

	meta := RouteMeta{
		SrcIP: util.IPToUint32(routeInfo.SrcIP),
	}
	copy(meta.SrcMAC[:], routeInfo.SrcMAC)

	// 2. 核心跨平台兼容逻辑：系统给了 MAC 就用，没给就主动发 ARP 去要！
	var dstMAC net.HardwareAddr
	if routeInfo.HardwareAddr != nil {
		dstMAC = routeInfo.HardwareAddr
	} else {
		// 确定下一跳 IP (如果是内网，下一跳就是目标；如果是公网，下一跳是网关)
		fmt.Printf("[*] 系统路由缓存未命中，启动主动 ARP 探测获取 %s 的 MAC...\n", nextHopIP.String())

		// 调用我们刚写的跨平台主动 ARP 函数
		mac, err := routing.ActiveARPResolution(routeInfo.Interface.Name, routeInfo.SrcIP, routeInfo.SrcMAC, nextHopIP)
		if err != nil {
			return 0, fmt.Errorf("无法解析下一跳 MAC: %v", err)
		}
		dstMAC = mac
	}

	copy(meta.DstMAC[:], dstMAC)

	GlobalRouteCache = append(GlobalRouteCache, meta)
	newRouteID := uint16(len(GlobalRouteCache) - 1)
	g.routeMap[cacheKey] = newRouteID

	return newRouteID, nil
}
