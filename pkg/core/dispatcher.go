package core

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"syscall"
)

func (e *Engine) RunDispatchers(ctx context.Context) {
	for {
		// 【绝对性能】：零拷贝读取，packetData 每次循环都会被复用/覆盖
		packetData, _, err := e.pcapHandle.ZeroCopyReadPacketData()
		if err != nil {
			continue // 处理超时或其他底层错误
		}
		if len(packetData) < 34 {
			continue
		}
		// 假设是以太网帧 (EthernetType == IPv4 0x0800)
		if packetData[12] != 0x08 || packetData[13] != 0x00 {
			continue
		}
		// 计算 IP 头真实长度
		ihl := packetData[14] & 0x0F
		ipHeaderLen := int(ihl) * 4
		if len(packetData) < 14+ipHeaderLen+4 { // 确保有足够的长度读端口
			continue
		}
		ipProtocol := packetData[23]
		var channelID uint16
		var packetSrcPort uint16
		// 1. 提取对方发送的 源端口 和 目标端口(ChannelID)
		switch ipProtocol {
		case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
			channelID = binary.BigEndian.Uint16(packetData[14+ipHeaderLen+2 : 14+ipHeaderLen+4])
			packetSrcPort = binary.BigEndian.Uint16(packetData[14+ipHeaderLen : 14+ipHeaderLen+2])
		case 1: // ICMP
			// ICMP 将 Identifier 视作 ChannelID，且没有源端口概念，设为 0
			channelID = binary.BigEndian.Uint16(packetData[14+ipHeaderLen+4 : 14+ipHeaderLen+6])
			packetSrcPort = 0
		default:
			continue
		}
		if int(channelID) >= MaxCWNDLimit {
			continue // 背景噪音
		}
		// 2. 构造全物理坐标用于强校验
		packetSrcIP := binary.BigEndian.Uint32(packetData[26:30])
		actualTarget := (uint64(packetSrcIP) << 16) | uint64(packetSrcPort)
		// 3. 【绝对壁垒】：O(1) 物理坐标校验
		expectedTarget := atomic.LoadUint64(&e.Targets[channelID])
		if actualTarget != expectedTarget {
			continue // 丢弃幽灵包
		}
		// 4. 特征坍缩：瞬间提取 32 位标量
		ipv4Header := packetData[14 : 14+ipHeaderLen]
		transportHeader := packetData[14+ipHeaderLen:]
		tensor := ExtractTensor(ipv4Header, transportHeader)
		// 5. 无锁瞬间唤醒
		select {
		case e.Channels[channelID] <- tensor:
		default:
		}
	}
}
