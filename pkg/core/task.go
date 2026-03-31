package core

import "syscall"

// EmissionTask 是完全塌缩后的扫描任务张量 (刚好 8 字节, 64 bits)
// 它在并发通道中传递，取代了原本臃肿的 *Target 结构体
type EmissionTask struct {
	TargetIP        uint32 // 目标 IPv4 (大端序)
	TargetPort      uint16 // 目标端口
	RouteID         uint16 // 指向全局只读路由表的索引，解决多网卡/多 MAC 问题
	Protocol        uint8  // syscall.IPPROTO_TCP, UDP, ICMP 等
	ScanFlags       uint8  // TCP 标志位 (如 SYN 0x02, ACK 0x10)
	IsHostDiscovery bool   //是否为探活任务
}

// RouteMeta 存储 L2/L3 物理链路层信息
// 这些信息是被多个相同网段的 EmissionTask 共享的
type RouteMeta struct {
	SrcIP  uint32  // 我们的发包源 IP
	SrcMAC [6]byte // 本机网卡 MAC
	DstMAC [6]byte // 下一跳 MAC (可能是网关，也可能是目标主机的直接 MAC)
	// 如果你使用 raw socket 绑定特定网卡发包，这里可以加一个 IfaceIndex
}

// 全局/引擎级的只读路由缓存表
// 使用切片通过 RouteID 进行 O(1) 访问
var GlobalRouteCache []RouteMeta

func (t PacketTensor) IsHostAlive(probeProtocol uint8) bool {
	proto := t.DecodeProtocol()
	flags := t.DecodeFlags()

	if probeProtocol == 1 && proto == 1 {
		return true
	}

	if probeProtocol == syscall.IPPROTO_TCP && proto == syscall.IPPROTO_TCP {
		if flags == (FlagSYN|FlagACK) || (flags&FlagRST) != 0 {
			return true
		}
	}

	if probeProtocol == syscall.IPPROTO_UDP && proto == syscall.IPPROTO_UDP {
		return true
	}
	return false
}
