/*
pkg/scanner/engine.go
这个文件实现了raw socket引擎，作用于绕过OS协议栈发送和接收自定义的网络包。
raw socket引擎的目的是，在用户空间中完成构建IP/TCP/UDP/ICMP等协议的网络包，
可以避免内核的TCP/IP协议栈干扰，直接构建出完整包发送、接收提高灵活性和效率
库：syscall    	-> Go的系统调用接口，使用socket操作
   gopacket   	-> 用于包构建/解析，简化layers
*/

package scanner

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
	"os"
	"runtime"
	"syscall"
)

// RawSocketEngine 结构体：use for Manage send and receive for raw socket 文件描述符(FD)
// sendFD: use for send socket ; recvFD use for receive socket
type RawSocketEngine struct {
	sendFD int //文件描述符(int) ,use for sendto()
	recvFD int // use for receive
}

// NewRawSocketEngine  创建raw socket 引擎
// Args protocol:接收协议，例如:IPPROTO_ICMP 或 IPPROTO_TCP
// return *RawSocketEngine / error
func NewRawSocketEngine(protocol int) (*RawSocketEngine, error) {

	//create for send socket , IPPROTO_RAW :允许构建完整IP包
	sendFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("create send socket: %v", err)
	}
	//？
	if runtime.GOOS == "darwin" {
		err = syscall.SetsockoptInt(sendFD, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if err != nil {
			return nil, fmt.Errorf("set IP_HDRINCL:  %v", err)
		}
	}

	//create for receive socket , 协议为输入参数，自定义
	recvFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, fmt.Errorf("create recv socket: %v", err)
	}

	//return 结构体指针
	return &RawSocketEngine{sendFD, recvFD}, nil
}

// SendPacket send for customized packet
// Args target :目标IP;packet:完整包字节（IP头 + 负载）
// 使用syscall.Sendto(fd,buf,flags,addr)
// addr : SockaddrInet4
func (e *RawSocketEngine) SendPacket(target net.IP, packet []byte) error {

	addr := syscall.SockaddrInet4{Addr: [4]byte(target.To4())}
	return syscall.Sendto(e.sendFD, packet, 0, &addr) //发送，无 flags
}

// ReceivePackets 接受响应包
// Args results :chan []byte use for received bytes
// 循环读取 buf（1500字节，典型 MTU），发送到chan
// raw socket 接收所有匹配协议的包，包括无意义包->进行后期过滤
func (e *RawSocketEngine) ReceivePackets(results chan<- []byte) {
	// uintptr(fd)：转为无符号指针。
	f := os.NewFile(uintptr(e.recvFD), fmt.Sprintf("%d", e.sendFD))
	buf := make([]byte, 1500)
	for {
		n, err := f.Read(buf)
		if err != nil {
			fmt.Println("Receive error :%v\n", err)
			break
		}
		results <- buf[:n]
	}
}

// BuildIPHeader 构建IP头
// Args:scrIP/dstIP:源/目标IP;protocol:TCP/ICMP... totalLen:总长度 ip头+负载
// return : []byte IP 头
// 网络概念：IP 头结构（RFC 791）：版本/IHL (0x45 = IPv4 + 5*4=20 字节头)，TTL (64)，协议，源/目标 IP 等。
// checksum: 校验和计算。
// macOS 适配：手动填充 totalLen（LittleEndian）、ID（随机）、checksum。
func BuildIPHeader(scrIP, dstIP net.IP, protocol layers.IPProtocol, totalLen uint16) []byte {
	ipHeader := make([]byte, 20) //分配20字节
	ipHeader[0] = 0x45           //版本 4 + IHL 5 （20字节/4 = 5）
	ipHeader[8] = 64             //TTL：跳数限制
	ipHeader[9] = byte(protocol) //协议号

	copy(ipHeader[12:16], scrIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	//macOS 适配 ：手动设置长度、ID、checksum

	if runtime.GOOS == "darwin" {
		binary.BigEndian.PutUint16(ipHeader[2:4], totalLen)
		binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65536)))
		binary.BigEndian.PutUint16(ipHeader[10:12], calculateIPChecksum(ipHeader))
	}

	return ipHeader
}

// calculateIPChecksum 计算 IP 头校验和。
// 算法：每 16 位相加，进位折叠，取反。
// 网络概念：IP checksum 只覆盖头，确保传输完整。
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32                        // 32 位累加器，避免溢出。
	for i := 0; i < len(header); i += 2 { // 每 2 字节（16 位）循环。
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2])) // BigEndian: 网络大端序。
	}
	for sum > 0xffff { // 折叠进位。
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum) // 取反（1 的补码）。
}
