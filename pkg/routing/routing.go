package routing

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway" // 【新增依赖】用于跨平台获取网关
)

// RouterManager 路由管理器
type RouterManager struct {
	// 移除 gopacket/routing 依赖
	// router routing.Router

	// ARP 缓存
	arpCache sync.Map
}

var GlobalRouter *RouterManager

func InitRouter() error {
	// 不再调用 routing.New()
	GlobalRouter = &RouterManager{}
	return nil
}

type RouteInfo struct {
	Interface    *net.Interface   // 出口网卡对象
	SrcIP        net.IP           // 源IP
	SrcMAC       net.HardwareAddr // 源MAC
	Gateway      net.IP           // 下一跳网关IP (如果是直连，则为 nil)
	HardwareAddr net.HardwareAddr // 下一跳的真实 MAC
	Direct       bool             // 是否直连
}

// RouteTo 核心路由解析函数 (跨平台版)
func (rm *RouterManager) RouteTo(dst net.IP) (*RouteInfo, error) {

	// ---------------------------------------------------------
	// 步骤 1: 确定出口 IP (Source IP)
	// ---------------------------------------------------------
	// 使用 UDP Dial 技巧，让操作系统帮我们选路
	// 这不会产生实际网络流量
	conn, err := net.Dial("udp", dst.String()+":80")
	if err != nil {
		return nil, fmt.Errorf("unreachable destination: %v", err)
	}
	defer conn.Close()

	// 拿到本机出口 IP
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := localAddr.IP

	// ---------------------------------------------------------
	// 步骤 2: 确定出口网卡 (Interface)
	// ---------------------------------------------------------
	// 遍历所有网卡，找到拥有这个 IP 的那个
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifaceObj *net.Interface
	var srcNet *net.IPNet // 用于判断是否同网段

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			// addr 通常是 *net.IPNet (包含 IP 和 Mask)
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(srcIP) {
					ifaceObj = &iface
					srcNet = ipnet
					break
				}
			}
		}
		if ifaceObj != nil {
			break
		}
	}

	if ifaceObj == nil {
		return nil, fmt.Errorf("could not find interface for local IP %s", srcIP)
	}

	info := &RouteInfo{
		Interface: ifaceObj,
		SrcIP:     srcIP,
		SrcMAC:    ifaceObj.HardwareAddr,
	}

	// ---------------------------------------------------------
	// 步骤 3: 判断下一跳 (Gateway vs Direct)
	// ---------------------------------------------------------
	var nextHopIP net.IP

	// 判断目标是否在同一网段
	if srcNet.Contains(dst) {
		// 直连模式
		info.Direct = true
		info.Gateway = nil
		nextHopIP = dst
	} else {
		// 网关模式
		info.Direct = false

		// 使用 jackpal/gateway 获取默认网关
		gwIP, err := gateway.DiscoverGateway()
		if err != nil {
			// 如果获取失败，且不是同网段，通常意味着网络配置有问题
			// 或者在某些 VPN 环境下，这里可能需要回退逻辑
			return nil, fmt.Errorf("discover gateway failed: %v", err)
		}
		info.Gateway = gwIP
		nextHopIP = gwIP
	}

	// ---------------------------------------------------------
	// 步骤 4: 解析下一跳 MAC (Layer 2 ARP)
	// ---------------------------------------------------------
	mac, err := rm.resolveMAC(ifaceObj, srcIP, ifaceObj.HardwareAddr, nextHopIP)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MAC for %s: %v", nextHopIP, err)
	}
	info.HardwareAddr = mac

	return info, nil
}

// resolveMAC 与之前保持一致，不需要修改
func (rm *RouterManager) resolveMAC(iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP) (net.HardwareAddr, error) {
	targetIPStr := targetIP.String()

	// 1. 查缓存
	if val, ok := rm.arpCache.Load(targetIPStr); ok {
		return val.(net.HardwareAddr), nil
	}

	// 2. 查不到，执行 ARP 探测
	mac, err := sendARPRequest(iface, srcIP, srcMAC, targetIP)
	if err != nil {
		return nil, err
	}

	// 3. 写入缓存
	rm.arpCache.Store(targetIPStr, mac)
	return mac, nil
}

// sendARPRequest 与之前保持一致
func sendARPRequest(iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP) (net.HardwareAddr, error) {
	// 打开 Pcap (设置较短的超时)
	handle, err := pcap.OpenLive(iface.Name, 65536, false, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// 设置 BPF
	// 注意：在 macOS 上，BPF 语法是通用的，不用改
	err = handle.SetBPFFilter(fmt.Sprintf("arp and src host %s", targetIP.String()))
	if err != nil {
		return nil, err
	}

	// 构造 ARP Request
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// 读取回复
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	start := time.Now()

	for {
		if time.Since(start) > 1000*time.Millisecond {
			return nil, errors.New("ARP timeout")
		}

		packet, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return nil, err
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arpPacket, _ := arpLayer.(*layers.ARP)
			if arpPacket.Operation == layers.ARPReply && bytes.Equal(arpPacket.SourceProtAddress, targetIP.To4()) {
				return net.HardwareAddr(arpPacket.SourceHwAddress), nil
			}
		}
	}
}
