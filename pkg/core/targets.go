package core

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/routing"
	"Going_Scan/pkg/target"
	"Going_Scan/pkg/util"
	"fmt"
	"net"
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
func (g *TaskGenerator) GenerateBatch() []EmissionTask {
	rawIP := g.ipIterator.Next()
	if rawIP == nil {
		return nil
	}

	targetIPUint32 := util.IPToUint32(rawIP)

	routeID, err := g.resolveAndCacheRoute(rawIP)
	if err != nil {
		fmt.Printf("警告: 主机不可达或无法解析路由 %s: %v\n", rawIP.String(), err)
		return g.GenerateBatch()
	}

	tasks := make([]EmissionTask, 0, len(g.ports))
	for _, port := range g.ports {
		tasks = append(tasks, EmissionTask{
			TargetIP:   targetIPUint32,
			TargetPort: uint16(port),
			RouteID:    routeID,
			Protocol:   g.baseProtocol,
			ScanFlags:  g.baseScanFlags,
		})
	}
	return tasks
}

// resolveAndCacheRoute 处理最棘手的 MAC 地址和网关问题
func (g *TaskGenerator) resolveAndCacheRoute(targetIP net.IP) (uint16, error) {
	// 简单缓存策略：可以根据目标 IP 或子网做 Cache Key
	// 如果是外网 IP，很多时候都走默认网关，可以极大节省解析时间
	// 这里为了演示，我们假设每次调用你之前的 routing.GlobalRouter

	routeInfo, err := routing.GlobalRouter.RouteTo(targetIP)
	if err != nil {
		return 0, err
	}

	// 检查是否在之前的解析中已经存过一模一样的路由信息
	cacheKey := fmt.Sprintf("%s_%s", routeInfo.SrcMAC.String(), routeInfo.HardwareAddr.String())
	if id, exists := g.routeMap[cacheKey]; exists {
		return id, nil
	}

	// 如果是一个全新的路由路径，将其加入全局只读缓存
	meta := RouteMeta{
		SrcIP: util.IPToUint32(routeInfo.SrcIP),
	}
	copy(meta.SrcMAC[:], routeInfo.SrcMAC)

	if routeInfo.HardwareAddr != nil {
		copy(meta.DstMAC[:], routeInfo.HardwareAddr)
	} else {
		// 这里处理 ARP 失败的情况
		return 0, fmt.Errorf("ARP resolution failed")
	}

	GlobalRouteCache = append(GlobalRouteCache, meta)
	newRouteID := uint16(len(GlobalRouteCache) - 1)
	g.routeMap[cacheKey] = newRouteID

	return newRouteID, nil
}
