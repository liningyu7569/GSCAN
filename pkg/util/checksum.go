package util

// CalculateChecksum 计算基础的 16 位校验和 (IP头, ICMP头)
func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}

// CalculatePseudoHeaderChecksum 计算 TCP/UDP 的伪首部校验和
func CalculatePseudoHeaderChecksum(srcIP, dstIP uint32, protocol uint8, tcpUdpLen uint16, payload []byte) uint16 {
	var sum uint32

	// 伪首部: 源IP (4), 目的IP (4), 占位符(1) + 协议(1), 长度(2)
	sum += (srcIP >> 16) + (srcIP & 0xffff)
	sum += (dstIP >> 16) + (dstIP & 0xffff)
	sum += uint32(protocol)
	sum += uint32(tcpUdpLen)

	// 载荷 (TCP/UDP头部 + 实际数据)
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
