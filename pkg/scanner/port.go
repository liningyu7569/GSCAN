// pkg/scanner/port.go
// 这个文件实现了 TCP SYN 端口扫描。
// 网络概念：SYN 扫描（半开连接）：发送 SYN 包，检查响应（SYN-ACK: open；RST: closed；无: filtered）。
// 使用 gopacket 构建 IP + TCP 层。
// 教学：TCP.SetNetworkLayerForChecksum() 设置 IP 层用于 TCP checksum 计算。
// SerializeLayers() 序列化多层。
package scanner

import (
	"fmt"       // 输出。
	"math/rand" // 随机。
	"net"       // IP。
	"syscall"
	"time" // 超时。

	"github.com/google/gopacket"        // 包操作。
	"github.com/google/gopacket/layers" // 层。
)

// ScanTCPPort 测试 TCP 端口状态。
// 参数 target: IP 字符串；port: 端口号。
// 返回状态字符串（open/closed/filtered）或错误。
func ScanTCPPort(target string, port uint16) (string, error) {
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		return "error", fmt.Errorf("invalid IP: %s", target)
	}
	srcIP, err := getLocalIP() // 源 IP。
	if err != nil {
		return "error", err
	}
	// 创建 TCP 专用引擎。
	engine, err := NewRawSocketEngine(syscall.IPPROTO_TCP)
	if err != nil {
		return "error", err
	}

	// 构建 TCP 层：SYN=true，随机源端口/Seq。
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rand.Intn(65535-1024) + 1024), // 随机高端口（>1024，避免特权）。
		DstPort: layers.TCPPort(port),                         // 目标端口。
		SYN:     true,                                         // SYN 标志。
		Window:  1024,                                         // 窗口大小。
		Seq:     rand.Uint32(),                                // 随机序列号。
	}
	// 构建 IP 层。
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}
	tcp.SetNetworkLayerForChecksum(&ip) // 设置 IP 层，用于 TCP checksum 计算（伪头）。

	// 序列化 IP + TCP。
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &ip, &tcp)

	// 发送序列化包。
	err = engine.SendPacket(dstIP, buf.Bytes())
	if err != nil {
		return "error", err
	}

	// 接收响应。
	results := make(chan []byte)
	go engine.ReceivePackets(results)
	select {
	case resp := <-results:
		// 解析响应。
		packet := gopacket.NewPacket(resp, layers.LayerTypeIPv4, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcpResp, _ := tcpLayer.(*layers.TCP)
			// 检查标志：SYN+ACK = open；RST = closed。
			if tcpResp.SYN && tcpResp.ACK {
				return "open", nil
			} else if tcpResp.RST {
				return "closed", nil
			}
		}
		return "filtered", nil // 其他 = filtered。
	case <-time.After(2 * time.Second):
		return "filtered", nil // 超时 = filtered。
	}
}
