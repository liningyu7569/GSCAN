package core

import (
	"encoding/binary"
	"syscall"
)

// PacketTensor 32位极限压缩特征，全程零 GC 压力
type PacketTensor uint32

// TensorTimeout 是一个特殊的魔术字，代表探针超时
const TensorTimeout PacketTensor = 0xFFFFFFFF

// 张量位移常量
const (
	ShiftTTL      = 8
	ShiftWinSize  = 16
	ShiftProtocol = 20
)

// TCP 标志位常量 (对应 Bits 0-7)
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
)

// ExtractTensor 在接收器 (Dispatcher) 中被调用
// 完全消除 if-else 的深度解析，O(1) 坍缩报文
func ExtractTensor(ipv4Header []byte, transportHeader []byte) PacketTensor {
	var tensor PacketTensor

	// 1. 提取回包协议 (IP 头第 10 字节)
	protocol := ipv4Header[9]
	tensor |= PacketTensor(protocol) << ShiftProtocol

	// 2. 提取 TTL (IP 头第 9 字节)
	ttl := ipv4Header[8]
	tensor |= PacketTensor(ttl) << ShiftTTL

	// 3. 提取传输层特征
	switch protocol {
	case syscall.IPPROTO_TCP:
		if len(transportHeader) >= 16 {
			// 提取 TCP Flags (TCP 头第 14 字节)
			flags := transportHeader[13]
			tensor |= PacketTensor(flags)

			// 提取 Window Size 并量化
			winSize := binary.BigEndian.Uint16(transportHeader[14:16])
			tensor |= PacketTensor(quantizeWindow(winSize)) << ShiftWinSize
		}

	case 1: // syscall.IPPROTO_ICMP
		if len(transportHeader) >= 1 {
			// 提取 ICMP Type (ICMP 头第 1 字节)
			// Type 3 通常代表 Destination Unreachable (端口不可达/被过滤)
			icmpType := transportHeader[0]
			tensor |= PacketTensor(icmpType)
		}

	case syscall.IPPROTO_UDP:
		// 如果收到纯 UDP 回包，通常意味着端口绝对开放
		tensor |= 0x01 // 赋予一个虚拟标志位代表有回包
	}

	return tensor
}

// quantizeWindow 将 16 位窗口压缩为 4 位，提取关键指纹特征
func quantizeWindow(win uint16) uint32 {
	switch {
	case win == 0:
		return 0
	case win < 1024:
		return 1
	case win < 8192:
		return 2
	default:
		return 3 // > 8192 (常作为 Windows 判定特征)
	}
}

// ---------------------------------------------------------
// 下方是提供给 探针 (Probe) 使用的极速解码方法
// ---------------------------------------------------------

// DecodeProtocol 解析回包协议
func (t PacketTensor) DecodeProtocol() uint8 {
	return uint8((t >> ShiftProtocol) & 0xFF)
}

// DecodeFlags 解析底层标志位
func (t PacketTensor) DecodeFlags() uint8 {
	return uint8(t & 0xFF)
}

// IsTCPStateOpen 判断端口是否为 Open
func (t PacketTensor) IsTCPStateOpen() bool {
	proto := t.DecodeProtocol()
	flags := t.DecodeFlags()
	// TCP SYN+ACK (0x12) -> 端口开放
	if proto == syscall.IPPROTO_TCP && flags == (FlagSYN|FlagACK) {
		return true
	}
	return false
}

// IsTCPStateClosed 判断端口是否为 Closed
func (t PacketTensor) IsTCPStateClosed() bool {
	proto := t.DecodeProtocol()
	flags := t.DecodeFlags()
	// 收到 RST (带有或不带 ACK) -> 端口关闭
	if proto == syscall.IPPROTO_TCP && (flags&FlagRST) != 0 {
		return true
	}
	return false
}
