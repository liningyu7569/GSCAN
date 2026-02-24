package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/routing"
	"Going_Scan/pkg/target"
	"Going_Scan/pkg/ulit"
	"fmt"
	"net/netip"
)

type HostGroupState struct {
	maxBatchSize int
	rawIterator  target.Iterator
	// ... 其他字段简化，目前主要用这两个
}

func NewHostGroupState(iterator target.Iterator, batchSize int) *HostGroupState {
	return &HostGroupState{
		rawIterator:  iterator,
		maxBatchSize: batchSize,
	}
}

// GetNextBatch 获取下一批准备好的 Target
// 返回 nil 表示所有目标都处理完了
func (h *HostGroupState) GetNextBatch() []*target.Target {
	batch := make([]*target.Target, 0, h.maxBatchSize)

	// 1. 从迭代器拉取原始 IP
	for len(batch) < h.maxBatchSize {
		rawIP := h.rawIterator.Next()
		if rawIP == nil {
			break // 没 IP 了
		}

		// 转换 IP 格式
		// 注意：rawIP 是 net.IP (slice)，Target 需要 netip.Addr (struct)
		addr, _ := netip.ParseAddr(rawIP.String())
		// 或者用你的 ulit 工具: addr, _ := ulit.StdIPToNetip(rawIP)

		t := target.NewTarget(addr)
		if conf.GlobalOps.Synscan || conf.GlobalOps.Connectscan || conf.GlobalOps.Ackscan || conf.GlobalOps.Windowscan {
			t.InitProtocolState(ProtocolTCP, GlobalPorts.Maps[ProtocolTCP].Count())
		}
		if conf.GlobalOps.Udpscan {
			t.InitProtocolState(ProtocolUDP, GlobalPorts.Maps[ProtocolUDP].Count())
		}
		batch = append(batch, t)
	}

	if len(batch) == 0 {
		return nil // 彻底结束
	}

	// 2. 批量预处理 (Hooks)
	// h.hookMassPing(batch) // 暂未实现
	// h.hookReverseDNS(batch) // 暂未实现
	h.hookResolveRouting(batch)

	// 3. 过滤掉死机/不可达的主机
	validBatch := make([]*target.Target, 0, len(batch))
	for _, t := range batch {
		if t.Status != target.HostDown {
			validBatch = append(validBatch, t)
		}
	}

	return validBatch
}

func (h *HostGroupState) hookResolveRouting(batch []*target.Target) {
	for _, t := range batch {
		// 查询路由
		stdIP := ulit.NetipToStdIP(t.TargetIpAddr())
		routeInfo, err := routing.GlobalRouter.RouteTo(stdIP)

		if err != nil {
			fmt.Printf("No route to host %s: %v\n", t.TargetIpAddr(), err)
			t.Status = target.HostDown
			continue
		}

		// 填充路由信息
		t.SetRouteInfo(
			routeInfo.Interface,
			routeInfo.SrcIP, // 本机出口 IP
			routeInfo.SrcMAC,
			routeInfo.Gateway,
			routeInfo.Direct, // 如果是直连，Gateway 为 nil (或目标MAC)
		)

		// 获取下一跳 MAC (NextHopMAC)
		// 这一步至关重要，否则 Injector 构建以太网帧时会崩溃
		// 如果路由说是直连，NextHopMAC 就是目标的 MAC (此时可能需要发 ARP 解析)
		// 如果是网关，NextHopMAC 就是网关的 MAC
		// 这里假设 GlobalRouter 已经帮我们搞定了 ARP 解析，或者 routeInfo.HardwareAddr 已经有了
		// 之前的代码片段
		if routeInfo.HardwareAddr != nil {
			// 这里的 HardwareAddr 就是 resolveMAC 返回的正确 MAC
			t.NextHopMAC = routeInfo.HardwareAddr
		} else {
			// 如果 resolveMAC 失败 (ARP 超时)，通常意味着网关不可达或者目标不可达
			// 标记为 HostDown 是合理的
			fmt.Printf("Warning: ARP resolution failed for %s\n", t.TargetIpAddr())
			t.Status = target.HostDown
		}

		// IP 伪造处理
		if conf.GlobalOps.SpoofIP != "" {
			addr, err := netip.ParseAddr(conf.GlobalOps.SpoofIP)
			if err == nil {
				t.SetSourcetIp(addr)
			}
		}
	}
}
