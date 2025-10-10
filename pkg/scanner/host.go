// // pkg/scanner/host.go
// // 这个文件实现了 ICMP Ping（主机发现）。
// // 如果回复，表示主机活跃。
// // 使用 gopacket 构建 ICMP 层，结合自定义 IP 头。
// package scanner
//
// import (
//
//	"fmt"
//	"net"
//	"syscall"
//	"time"
//
//	"github.com/google/gopacket"        // 包操作。
//	"github.com/google/gopacket/layers" // 层定义。
//
// )
//
// // PingHost 发送 ICMP Echo 测试主机活跃。
// // 参数 target: 字符串 IP。
// // 返回 bool（活跃）或错误。
// // 步骤：解析 IP，创建引擎，构建 ICMP，发送，接收并解析响应。
//
//	func PingHost(target string) (bool, error) {
//		dstIP := net.ParseIP(target) // 解析字符串到 net.IP。
//		if dstIP == nil {            // 如果无效，返回错误。
//			return false, fmt.Errorf("invalid IP: %s", target)
//		}
//		srcIP := net.ParseIP("127.0.0.1") // 源 IP：本地接口，可替换为实际。
//
//		// 创建 ICMP 专用引擎。
//		engine, err := NewRawSocketEngine(syscall.IPPROTO_ICMP)
//		if err != nil {
//			return false, err
//		}
//
//		// 构建 ICMP 层：TypeCode = 8/0 (Echo Request)。
//		icmp := layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
//		buf := gopacket.NewSerializeBuffer() // 创建序列化缓冲区。
//		// 序列化：FixLengths 自动修复长度；ComputeChecksums 计算校验和。
//		err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &icmp)
//		if err != nil {
//			return false, err
//		}
//
//		// 构建 IP 头：协议 ICMP，总长 20 (IP) + 8 (ICMP)。
//		ipHeader := BuildIPHeader(srcIP, dstIP, layers.IPProtocolICMPv4, 28)
//		packet := append(ipHeader, buf.Bytes()...) // 组合 IP + ICMP。
//
//		// 发送包。
//		err = engine.SendPacket(dstIP, packet)
//		if err != nil {
//			return false, err
//		}
//
//		// 接收：用 channel 接收响应，goroutine 运行 ReceivePackets。
//		results := make(chan []byte)      // 创建 channel。
//		go engine.ReceivePackets(results) // go: 启动 goroutine（并发）。
//		select {                          // select: 多路复用 channel。
//		case resp := <-results: // 收到响应。
//			// 解析包：LayerTypeIPv4 指定起始层。
//			packet := gopacket.NewPacket(resp, layers.LayerTypeIPv4, gopacket.Default)
//			// 获取 ICMP 层。
//			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
//				icmp, _ := icmpLayer.(*layers.ICMPv4) // 类型断言。
//				// 检查 Type 是否 Echo Reply。
//				if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
//					return true, nil
//				}
//			}
//		case <-time.After(2 * time.Second): // 超时 channel。
//		}
//		return false, nil // 无回复，返回 false。
//	}
//
// pkg/scanner/engine.go// pkg/scanner/host.go
package scanner

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PingHost(target string) (bool, error) {
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		return false, fmt.Errorf("invalid IP: %s", target)
	}
	srcIP, err := getLocalIP()
	if err != nil {
		return false, fmt.Errorf("get local IP: %v", err)
	}
	fmt.Printf("Pinging %s from %s\n", target, srcIP) // 日志：源/目标 IP

	engine, err := NewRawSocketEngine(syscall.IPPROTO_ICMP)
	if err != nil {
		return false, err
	}

	icmp := layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &icmp)
	fmt.Printf("ICMP payload: %x\n", buf.Bytes()) // 日志：ICMP 负载

	ipHeader := BuildIPHeader(srcIP, dstIP, layers.IPProtocolICMPv4, 28)
	packet := append(ipHeader, buf.Bytes()...)
	fmt.Printf("Full packet: %x\n", packet) // 日志：完整包

	err = engine.SendPacket(dstIP, packet)
	if err != nil {
		return false, err
	}

	results := make(chan []byte)
	go engine.ReceivePackets(results)
	select {
	case resp := <-results:
		fmt.Printf("Received response: %x\n", resp)
		packet := gopacket.NewPacket(resp, layers.LayerTypeIPv4, gopacket.Default)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				return true, nil
			}
		}
	case <-time.After(5 * time.Second):
		fmt.Println("Timeout waiting for response")
	}
	return false, nil
}

func getLocalIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("no valid local IP")
}
