package scanner

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketReceiver struct {
	ResultChan chan<- RecvEvent
	handle     *pcap.Handle
}

func NewReceiver(ch chan<- RecvEvent, handle *pcap.Handle) *PacketReceiver {
	return &PacketReceiver{
		ResultChan: ch,
		handle:     handle,
	}
}

func (rcv *PacketReceiver) Run() {

	//内存复用
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var icmp4 layers.ICMPv4
	//1，注册解析器
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip4, &tcp, &udp, &icmp4)

	//遇错不停止，继续解析
	parser.IgnoreUnsupported = true

	decoded := []gopacket.LayerType{}
	source := gopacket.NewPacketSource(rcv.handle, rcv.handle.LinkType())

	for packet := range source.Packets() {
		//2，解析包，零拷贝
		err := parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
		}
		evt := RecvEvent{
			RecvTime: packet.Metadata().CaptureInfo.Timestamp,
		}
		foundTransport := false
		//遍历解析出的层
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				evt.SrcIP = ip4.SrcIP.String()

			case layers.LayerTypeTCP:
				evt.Protocol = ProtocolTCP
				evt.SrcPort = int(tcp.SrcPort)
				evt.Seq = tcp.Seq
				evt.Ack = tcp.Ack
				evt.Flags = parseTCPFlags(&tcp)
				foundTransport = true

			case layers.LayerTypeUDP:
				evt.Protocol = ProtocolUDP
				evt.SrcPort = int(udp.SrcPort)
				foundTransport = true

			case layers.LayerTypeICMPv4:
				// 【新增】ICMP 核心逻辑
				evt.Protocol = ProtocolICMP
				evt.ICMPType = icmp4.TypeCode.Type()
				evt.ICMPCode = icmp4.TypeCode.Code()

				// 深度解析：提取“原始数据包”信息
				// ICMP 错误包的 Payload 包含了出错那个包的 IP 头 + 前 8 字节
				// 我们需要从中提取出我们当初探测的 DstPort
				extractedPort := extractOriginalDstPort(icmp4.Payload)
				if extractedPort > 0 {
					evt.SrcPort = extractedPort
					foundTransport = true
				}
			}
		}
		if foundTransport {
			select {

			case rcv.ResultChan <- evt:
			default:
			}
		}
	}
}

func extractOriginalDstPort(payload []byte) int {
	if len(payload) < 20 {
		return 0
	}
	// 1. 解析内部 IP 头长度
	// IP 头第一个字节: Version(4bit) + IHL(4bit)
	// IHL 单位是 4 字节
	ihl := int(payload[0]&0x0f) * 4

	if len(payload) < ihl+4 { // 至少要有 IP 头 + 端口号位置
		return 0
	}

	// 2. 提取端口
	// 无论是 TCP 还是 UDP，目的端口 (DstPort) 都在 Header 的第 2-3 字节 (偏移量 2)
	// 注意：原始包是我们发出去的，所以我们要找的是 *Destination Port*
	// 在 ICMP 载荷里，它位于 IP 头之后
	portBytes := payload[ihl+2 : ihl+4]
	return int(binary.BigEndian.Uint16(portBytes))
}

func parseTCPFlags(tcp *layers.TCP) uint8 {
	var f uint8
	if tcp.SYN {
		f |= 0x02
	}
	if tcp.ACK {
		f |= 0x10
	}
	if tcp.FIN {
		f |= 0x01
	}
	if tcp.RST {
		f |= 0x04
	}
	if tcp.PSH {
		f |= 0x08
	}
	if tcp.URG {
		f |= 0x20
	}
	return f
}
