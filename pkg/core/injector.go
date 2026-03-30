package core

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/util"
)

const (
	EthernetLen = 14
	IPv4Len     = 20
	TCPLen      = 20
	UDPLen      = 8
	ICMPLen     = 8
)

// BuildIntoBuffer 瞬间组装数据包。直接操作传入的指针所指向的底层数组，
// 仅返回实际封包长度，彻底阻断逃逸分析，实现绝对零分配。
func BuildIntoBuffer(bufPtr *[]byte, task EmissionTask, channelID uint16, route RouteMeta) (int, error) {
	// 解引用获取底层切片，无需重新分配
	buf := *bufPtr

	// 防御性校验
	if len(buf) < 54 {
		return 0, fmt.Errorf("buffer capacity too small")
	}

	// 1. 预判总长度
	var totalLen uint16 = EthernetLen + IPv4Len
	var ipProto uint8

	switch task.Protocol {
	case syscall.IPPROTO_TCP:
		totalLen += TCPLen
		ipProto = syscall.IPPROTO_TCP
	case syscall.IPPROTO_UDP:
		totalLen += UDPLen
		ipProto = syscall.IPPROTO_UDP
	case 1: // ICMP
		totalLen += ICMPLen
		ipProto = 1
	default:
		return 0, fmt.Errorf("unsupported protocol: %d", task.Protocol)
	}

	// 截取当前协议需要的精确切片以供写入
	packet := buf[:totalLen]
	encodedPort := encodeChannelPort(channelID)
	ttl := uint8(64)
	if conf.GlobalOps.TTL > 0 && conf.GlobalOps.TTL <= 255 {
		ttl = uint8(conf.GlobalOps.TTL)
	}

	// -----------------------------------------------------
	// Layer 2: Ethernet Header (14 Bytes)
	// -----------------------------------------------------
	copy(packet[0:6], route.DstMAC[:])
	copy(packet[6:12], route.SrcMAC[:])
	binary.BigEndian.PutUint16(packet[12:14], 0x0800) // EtherType: IPv4

	// -----------------------------------------------------
	// Layer 3: IPv4 Header (20 Bytes)
	// -----------------------------------------------------
	ipLayer := packet[14:34]
	ipLayer[0] = 0x45                                              // Version (4) + IHL (5 * 4 = 20)
	ipLayer[1] = 0x00                                              // TOS
	binary.BigEndian.PutUint16(ipLayer[2:4], totalLen-EthernetLen) // Total Length (IP + Transport)
	binary.BigEndian.PutUint16(ipLayer[4:6], uint16(task.TargetPort)^encodedPort)
	binary.BigEndian.PutUint16(ipLayer[6:8], 0x4000) // Flags: DF, Fragment Offset: 0
	ipLayer[8] = ttl
	ipLayer[9] = ipProto                          // Protocol
	binary.BigEndian.PutUint16(ipLayer[10:12], 0) // 校验和置零
	binary.BigEndian.PutUint32(ipLayer[12:16], route.SrcIP)
	binary.BigEndian.PutUint32(ipLayer[16:20], task.TargetIP)

	// 计算 IP 层校验和
	ipChecksum := util.CalculateChecksum(ipLayer)
	binary.BigEndian.PutUint16(ipLayer[10:12], ipChecksum)

	// -----------------------------------------------------
	// Layer 4: Transport Layer
	// -----------------------------------------------------
	transportLayer := packet[34:totalLen]

	switch task.Protocol {
	case syscall.IPPROTO_TCP:
		binary.BigEndian.PutUint16(transportLayer[0:2], encodedPort)
		binary.BigEndian.PutUint16(transportLayer[2:4], task.TargetPort)
		binary.BigEndian.PutUint32(transportLayer[4:8], (uint32(channelID)<<16)|uint32(task.TargetPort))
		binary.BigEndian.PutUint32(transportLayer[8:12], 0)
		transportLayer[12] = 0x50
		transportLayer[13] = task.ScanFlags
		binary.BigEndian.PutUint16(transportLayer[14:16], 1024)
		binary.BigEndian.PutUint16(transportLayer[16:18], 0)
		binary.BigEndian.PutUint16(transportLayer[18:20], 0)

		tcpChecksum := util.CalculatePseudoHeaderChecksum(route.SrcIP, task.TargetIP, syscall.IPPROTO_TCP, TCPLen, transportLayer)
		binary.BigEndian.PutUint16(transportLayer[16:18], tcpChecksum)

	case syscall.IPPROTO_UDP:
		binary.BigEndian.PutUint16(transportLayer[0:2], encodedPort)
		binary.BigEndian.PutUint16(transportLayer[2:4], task.TargetPort)
		binary.BigEndian.PutUint16(transportLayer[4:6], UDPLen)
		binary.BigEndian.PutUint16(transportLayer[6:8], 0)

		udpChecksum := util.CalculatePseudoHeaderChecksum(route.SrcIP, task.TargetIP, syscall.IPPROTO_UDP, UDPLen, transportLayer)
		binary.BigEndian.PutUint16(transportLayer[6:8], udpChecksum)

	case 1: // ICMP
		transportLayer[0] = 8
		transportLayer[1] = 0
		binary.BigEndian.PutUint16(transportLayer[2:4], 0)
		binary.BigEndian.PutUint16(transportLayer[4:6], encodedPort)
		binary.BigEndian.PutUint16(transportLayer[6:8], 1)

		icmpChecksum := util.CalculateChecksum(transportLayer)
		binary.BigEndian.PutUint16(transportLayer[2:4], icmpChecksum)
	}

	// 返回实际装填的字节数
	return int(totalLen), nil
}
