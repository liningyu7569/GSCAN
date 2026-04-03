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
	ipIterator target.Iterator
	ports      []int
	routeMap   map[string]uint16

	// 提前固化的全局协议参数
	baseProtocol  uint8
	baseScanFlags uint8
}

const shardCount = 256

type hdShard struct {
	sync.Mutex
	m map[uint32]struct{}
}

var (
	hdFilter    [shardCount]*hdShard
	HDReservoir = queue.NewLockFreeRingBuffer[uint32](65536)
	TestIP      []net.IP
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
	return true // 首次发现存活
}

// NewTaskGenerator 读取 conf.GlobalOps，固化本次扫描的协议策略
func NewTaskGenerator(iter target.Iterator, ports []int) *TaskGenerator {
	gen := &TaskGenerator{
		ipIterator: iter,
		ports:      ports,
		routeMap:   make(map[string]uint16),
	}

	// 初始化单次扫描的协议与标志位
	// 预留：如果未来要在一次扫描中混合多种协议，需将此逻辑下放到 GenerateBatch 的端口循环中
	if conf.GlobalOps.Synscan {
		gen.baseProtocol = syscall.IPPROTO_TCP
		gen.baseScanFlags = 0x02 // SYN
	} else if conf.GlobalOps.Ackscan {
		gen.baseProtocol = syscall.IPPROTO_TCP
		gen.baseScanFlags = 0x10 // ACK
	} else if conf.GlobalOps.Udpscan {
		gen.baseProtocol = syscall.IPPROTO_UDP
		gen.baseScanFlags = 0x00
	} else {
		// 默认缺省为 TCP SYN
		gen.baseProtocol = syscall.IPPROTO_TCP
		gen.baseScanFlags = 0x02
	}

	return gen
}
func (g *TaskGenerator) GenerateBatch() ([]EmissionTask, bool) {

	// 1. 检查探活开关 (类似 Nmap 的 -Pn)
	if conf.GlobalOps.SkipHostDiscovery {
		// 跳过探活，直接从迭代器拿 IP 生成端口扫描任务
		rawIP := g.ipIterator.Next()
		if rawIP == nil {
			return nil, true
		}
		return g.generatePortScanTasks(util.IPToUint32(rawIP)), false
	}

	var aliveIP uint32
	if HDReservoir.Pop(&aliveIP) {
		return g.generatePortScanTasks(aliveIP), false
	}
	rawIP := g.ipIterator.Next()
	TestIP = append(TestIP, rawIP)
	if rawIP != nil {
		return g.generateHostDiscoveryTasks(util.IPToUint32(rawIP), rawIP), false
	}
	return nil, true
	//
	//routeID, err := g.resolveAndCacheRoute(rawIP)
	//if err != nil {
	//	fmt.Printf("警告: 主机不可达或无法解析路由 %s: %v\n", rawIP.String(), err)
	//	return g.GenerateBatch()
	//}
	//
	//tasks := make([]EmissionTask, 0, len(g.ports))
	//for _, port := range g.ports {
	//	tasks = append(tasks, EmissionTask{
	//		TargetIP:   targetIPUint32,
	//		TargetPort: uint16(port),
	//		RouteID:    routeID,
	//		Protocol:   g.baseProtocol,
	//		ScanFlags:  g.baseScanFlags,
	//	})
	//}
	//return tasks
}

// generatePortScanTasks 生成真正的端口扫描弹药
func (g *TaskGenerator) generatePortScanTasks(targetIPUint32 uint32) []EmissionTask {
	rawIP := util.Uint32ToIP(targetIPUint32)
	routeID, _ := g.resolveAndCacheRoute(rawIP)

	tasks := make([]EmissionTask, 0, len(g.ports))
	for _, port := range g.ports {
		tasks = append(tasks, EmissionTask{
			TargetIP:        targetIPUint32,
			TargetPort:      uint16(port),
			RouteID:         routeID,
			Protocol:        g.baseProtocol,
			ScanFlags:       g.baseScanFlags,
			IsHostDiscovery: false, // 标记为真实扫描
		})
	}
	return tasks
}

func (g *TaskGenerator) generateHostDiscoveryTasks(targetIPUint32 uint32, rawIP net.IP) []EmissionTask {
	routeID, _ := g.resolveAndCacheRoute(rawIP)
	tasks := make([]EmissionTask, 0, 2)

	// 探针 A: ICMP
	tasks = append(tasks, EmissionTask{
		TargetIP:        targetIPUint32,
		TargetPort:      0,
		RouteID:         routeID,
		Protocol:        1,    // ICMP
		IsHostDiscovery: true, // 打上探活标记
	})

	// 探针 B: TCP 80
	tasks = append(tasks, EmissionTask{
		TargetIP:        targetIPUint32,
		TargetPort:      80,
		RouteID:         routeID,
		Protocol:        syscall.IPPROTO_TCP,
		ScanFlags:       0x02, // SYN
		IsHostDiscovery: true,
	})

	return tasks
}
func (g *TaskGenerator) resolveAndCacheRoute(targetIP net.IP) (uint16, error) {
	// 1. 调用系统路由表查找下一跳
	routeInfo, err := routing.GlobalRouter.RouteTo(targetIP)
	if err != nil {
		return 0, err
	}

	cacheKey := fmt.Sprintf("%s_%s", routeInfo.Interface.Name, targetIP.String())
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
		nextHopIP := routeInfo.Gateway
		if nextHopIP == nil {
			nextHopIP = targetIP
		}

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
