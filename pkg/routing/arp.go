package routing

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ActiveARPResolution 跨平台主动 ARP 探测
// 当操作系统的路由表无法提供下一跳 MAC 时，我们主动发 ARP 去问
func ActiveARPResolution(ifaceName string, srcIP net.IP, srcMAC net.HardwareAddr, targetIP net.IP) (net.HardwareAddr, error) {
	// 1. 打开指定网卡的 Pcap 句柄
	handle, err := pcap.OpenLive(ifaceName, 65536, true, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// 2. 设置严格的 BPF 过滤器，只接收我们要的 ARP 回应包
	// 过滤条件：ARP 协议，且发送方 IP 是我们要找的那个目标 IP
	filter := "arp and arp[7] = 2 and src host " + targetIP.String()
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	// 3. 构建手工 ARP Request 报文
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播 MAC
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
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0}, // 等待对方填入
		DstProtAddress:    []byte(targetIP.To4()),
	}

	// 序列化报文
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}

	// 4. 发送 ARP 请求
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// 5. 阻塞等待 ARP 回应 (带 2 秒超时)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(2 * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpReply := arpLayer.(*layers.ARP)
				// 二次确认：这是我们要找的 IP 回复的 MAC
				if bytes.Equal(arpReply.SourceProtAddress, targetIP.To4()) {
					return net.HardwareAddr(arpReply.SourceHwAddress), nil
				}
			}
		case <-timeout:
			return nil, errors.New("ARP resolution timeout")
		}
	}
}
