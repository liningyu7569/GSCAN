package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/ulit"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ConstructRawPacket(task SendTask) ([]byte, error) {

	//1,准备序列化缓冲区
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true, //自动计算Length字段
		ComputeChecksums: true, //自动计算Checksum
	}
	// -----------------------------------------------------
	// 1. Layer2:Ethernet / Link Layer
	// -----------------------------------------------------
	var linkLayer gopacket.SerializableLayer

	if task.Target.NextHopMAC != nil {
		eth := &layers.Ethernet{
			SrcMAC:       task.Target.SrcMac,
			DstMAC:       task.Target.NextHopMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		linkLayer = eth
	} else {
		return nil, fmt.Errorf("no link layer found")
	}
	// -----------------------------------------------------
	// 2. Layer3:IPv4
	// -----------------------------------------------------
	var ipProto layers.IPProtocol
	switch task.Protocol {
	case ProtocolTCP:
		ipProto = layers.IPProtocolTCP
	case ProtocolUDP:
		ipProto = layers.IPProtocolUDP
	case ProtocolICMP:
		ipProto = layers.IPProtocolICMPv4
	default:
		return nil, fmt.Errorf("unsupported protocol: %d", task.Protocol)
	}
	ip := &layers.IPv4{
		SrcIP:    ulit.NetipToStdIP(task.SrcIP),
		DstIP:    ulit.NetipToStdIP(task.Target.TargetIpAddr()),
		Version:  4,
		TTL:      64,
		Id:       uint16(task.Seq & 0xFFFF),
		Protocol: ipProto,
	}
	// -----------------------------------------------------
	// 2. Layer3:TCP
	// -----------------------------------------------------

	var transportLayer gopacket.SerializableLayer

	switch task.Protocol {
	case ProtocolTCP:
		//基源端口
		srcPort := getEncodedSourcePort(task.Port)

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(task.Port),
			Seq:     task.Seq,
			Ack:     task.Ack,
			Window:  1024,
			SYN:     (task.Flags & 0x02) != 0,
			ACK:     (task.Flags & 0x10) != 0,
			RST:     (task.Flags & 0x04) != 0,
			FIN:     (task.Flags & 0x01) != 0,
			PSH:     (task.Flags & 0x08) != 0,
			URG:     (task.Flags & 0x20) != 0,
		}
		//校验和计算
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil, err
		}
		transportLayer = tcp

	case ProtocolUDP:
		srcPort := getEncodedSourcePort(task.Port)

		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(task.Port),
			Length:  uint16(8 + len(task.Payload)),
		}

		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil, err
		}

		transportLayer = udp

	case ProtocolICMP:
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       uint16(task.Seq & 0xFFFF),
			Seq:      uint16(task.Seq >> 16),
		}
		transportLayer = icmp
	}
	//序列化
	var payloadLayer gopacket.SerializableLayer
	layersToSerialize := []gopacket.SerializableLayer{linkLayer, ip, transportLayer}
	if len(task.Payload) > 0 {
		payloadLayer = gopacket.Payload(task.Payload)
		layersToSerialize = append(layersToSerialize, payloadLayer)
	}

	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func getEncodedSourcePort(dstPort int) int {
	if conf.GlobalOps.SourcePort > 0 {
		return conf.GlobalOps.SourcePort
	}

	base := 33333 + (dstPort % 20000)
	if base > 65535 {
		base = 65535
	}
	return base
}
