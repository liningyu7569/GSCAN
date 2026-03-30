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
	"github.com/jackpal/gateway"
)

type RouterManager struct {
	arpCache sync.Map

	// 【V2 优化】：全局缓存默认网关，防止 jackpal/gateway 频繁调用 shell 导致性能雪崩
	defaultGateway net.IP
	gwOnce         sync.Once
}

var GlobalRouter *RouterManager

func InitRouter() error {
	GlobalRouter = &RouterManager{}
	return nil
}

type RouteInfo struct {
	DeviceName   string           // 网卡名称 (Pcap 监听需要)
	Interface    *net.Interface   // 出口网卡对象
	SrcIP        net.IP           // 源IP
	SrcMAC       net.HardwareAddr // 源MAC
	Gateway      net.IP           // 下一跳网关IP (如果是直连，则为 nil)
	HardwareAddr net.HardwareAddr // 下一跳的真实 MAC
	Direct       bool             // 是否直连
}

// GetDefaultInterface 获取默认联网的网卡和 IP (供 cmd/root.go 全局 Pcap 监听使用)
func GetDefaultInterface() *RouteInfo {
	// 使用 UDP Dial 连接极其稳定的公网地址，强制操作系统走默认路由
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := localAddr.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(srcIP) {
					return &RouteInfo{
						DeviceName: iface.Name,
						Interface:  &iface,
						SrcIP:      srcIP,
						SrcMAC:     iface.HardwareAddr,
					}
				}
			}
		}
	}
	return nil
}

// RouteTo 核心路由解析函数 (跨平台高性能版)
func (rm *RouterManager) RouteTo(dst net.IP) (*RouteInfo, error) {
	// 1. 确定出口 IP (Source IP)
	conn, err := net.Dial("udp", dst.String()+":80")
	if err != nil {
		return nil, fmt.Errorf("unreachable destination: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := localAddr.IP

	// 2. 确定出口网卡 (Interface)
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifaceObj *net.Interface
	var srcNet *net.IPNet

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
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
		DeviceName: ifaceObj.Name,
		Interface:  ifaceObj,
		SrcIP:      srcIP,
		SrcMAC:     ifaceObj.HardwareAddr,
	}

	// 3. 判断下一跳 (Gateway vs Direct)
	var nextHopIP net.IP

	if srcNet.Contains(dst) {
		// 直连模式 (同局域网)
		info.Direct = true
		info.Gateway = nil
		nextHopIP = dst
	} else {
		// 网关模式 (外网)
		info.Direct = false

		// 【V2 优化】：单例模式获取网关，极大提升扫公网时的性能
		rm.gwOnce.Do(func() {
			gwIP, _ := gateway.DiscoverGateway()
			rm.defaultGateway = gwIP
		})

		if rm.defaultGateway == nil {
			return nil, fmt.Errorf("discover gateway failed")
		}
		info.Gateway = rm.defaultGateway
		nextHopIP = rm.defaultGateway
	}

	// 4. 解析下一跳 MAC (Layer 2 ARP)
	mac, err := rm.resolveMAC(ifaceObj, srcIP, ifaceObj.HardwareAddr, nextHopIP)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MAC for %s: %v", nextHopIP, err)
	}
	info.HardwareAddr = mac

	return info, nil
}

// resolveMAC 缓存优先的 ARP 解析
func (rm *RouterManager) resolveMAC(iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, nextHopIP net.IP) (net.HardwareAddr, error) {
	targetIPStr := nextHopIP.String()

	if val, ok := rm.arpCache.Load(targetIPStr); ok {
		return val.(net.HardwareAddr), nil
	}

	mac, err := sendARPRequest(iface, srcIP, srcMAC, nextHopIP)
	if err != nil {
		return nil, err
	}

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
