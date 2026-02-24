package target

import (
	"Going_Scan/pkg/ulit"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// HostStatus 定义主机状态 (参考 Nmap: HOST_UP, HOST_DOWN)
type HostStatus int

const (
	HostUnknown HostStatus = iota
	HostUp
	HostDown
)

const (
	PUnkown = 10
	POpen   = 11
	PClose  = 12
	PFilter = 13
)

// PortState 定义端口状态
type PortState int

const (
	PortUnknown PortState = iota
	PortOpen
	PortClosed
	PortFiltered
)

// PortInfo 存储单个端口的详细信息
// 尽量保持紧凑，以便在大量端口时节省内存
type PortInfo struct {
	ID        uint16
	Protocol  string // "tcp", "udp"
	State     PortState
	Service   string // "http", "ssh"
	Reason    string // "syn-ack", "rst"
	Timestamp time.Time
}

// Target 是扫描的核心对象
// 对应 Nmap 的 C++ Target class
type Target struct {
	// --- 基础标识 (只读) ---
	// 使用 netip.Addr 是 Go 1.18+ 的最佳实践 (Value type, allocation-free)
	targetIp, sourceIp, NexthopeIp      netip.Addr
	targetSock, sourceSock, nextHopSock unix.Sockaddr
	// --- 链路层信息 (L2 Scanning 需要) ---
	// 用于存储解析到的 MAC 地址或网关 MAC
	SrcMac            net.HardwareAddr
	NextHopMAC        net.HardwareAddr // 如果是外网目标，这里存网关 MAC
	Iface             *net.Interface   // 出口网卡
	DirectylConnected bool             //是否直连

	// --- 状态信息 (并发读写) ---
	// 必须使用 RWMutex 保护，因为扫描协程会并发写入 Port 结果
	mu         sync.RWMutex
	Status     HostStatus
	hostnames  string
	targetname string
	//TTL
	distance int8
	//TTL估计方式
	distance_calculation_method int8
	//存储结果
	FPR         []string
	osscan_flag int8

	// 端口状态存储
	PortStates map[int][]uint8

	// OS 探测结果 (预留)
	osFingerprint string
}

// NewTarget 工厂函数
func NewTarget(ip netip.Addr) *Target {
	target := &Target{}
	target.setTargetIp(ip)
	target.PortStates = make(map[int][]uint8)
	target.Status = HostUnknown
	return target
}

// --- Public Wrapper Methods (Thread-Safe) ---

// 返回目标Sock (Public)
func (t *Target) TargetSockAddr() unix.Sockaddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.targetSockAddr()
}

// 设置目标Sock (Public)
func (t *Target) SetTargetSockAddr(sa unix.Sockaddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.setTargetSockAddr(sa)
}

// 返回源Sock (Public)
func (t *Target) SourceSockAddr() unix.Sockaddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sourceSockAddr()
}

// 返回源地址
func (t *Target) SourceIpAddr() netip.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sourceip()
}

// 返回目标地址
func (t *Target) TargetIpAddr() netip.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.targetip()
}

// 设置目标地址
func (t *Target) SetTargetIpAddr(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setTargetIp(ip)
}

// 设置源地址
func (t *Target) SetSourcetIp(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setSourceIp(ip)
}

func (t *Target) SetRouteInfo(iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, gateway net.IP, direct bool) {
	var err error
	t.Iface = iface
	t.sourceIp, err = ulit.StdIPToNetip(srcIP)
	if err != nil {
		fmt.Errorf("SrcIP to netip.Addr is error for %e", err)
	}
	t.SrcMac = srcMAC
	t.DirectylConnected = direct
	if direct {
		t.NexthopeIp = t.targetIp
	} else {
		t.NexthopeIp, err = ulit.StdIPToNetip(gateway)
		if err != nil {
			fmt.Errorf("NexrHopeIp_Gateway to netip.Addr is error for %e", err)
		}
	}
}

// 设置源Sock (Public)
func (t *Target) SetSourceSockAddr(sa unix.Sockaddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.setSourceSockAddr(sa)
}

// 设置TargetName (Public)
func (t *Target) SetTargetName(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setTargetName(name)
}

// 设置主机名 (Public)
func (t *Target) SetHostname(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setHostname(name)
}

// 查询端口状态
func (t *Target) GetPortInfo(protocol int, port int) uint {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.GetPortInfo(protocol, port)
}

// 初始化端口状态数组
func (t *Target) InitProtocolState(protocol int, count int) {
	if count > 0 {
		t.PortStates[protocol] = make([]uint8, count)
	}
}

// 设置端口状态
func (t *Target) SetPortInfo(protocol int, port uint, state uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setPortInfo(protocol, port, state)
}

// --- Private Logic Methods (No Locking) ---

// 返回目标Sock (Private)
func (t *Target) targetSockAddr() unix.Sockaddr {
	return t.targetSock
}

// 设置目标Sock (Private)
func (t *Target) setTargetSockAddr(sa unix.Sockaddr) error {
	if t.targetSock != nil {
		t.targetname = ""
		t.hostnames = ""
	}
	t.targetSock = sa
	ip, err := sockaddrToIP(sa)
	if err != nil {
		return fmt.Errorf("invalid Target_sockaddr :%w", err)
	}
	t.targetIp = ip

	return nil
}

// 返回源Sock (Private)
func (t *Target) sourceSockAddr() unix.Sockaddr {
	return t.sourceSock
}

func (t *Target) sourceip() netip.Addr {
	return t.sourceIp
}

func (t *Target) setTargetIp(ip netip.Addr) {
	t.targetIp = ip
}
func (t *Target) targetip() netip.Addr {
	return t.targetIp
}

// 设置源Sock (Private)
func (t *Target) setSourceSockAddr(sa unix.Sockaddr) error {
	t.sourceSock = sa
	ip, err := sockaddrToIP(sa)
	if err != nil {
		return fmt.Errorf("invalid Source_sockaddr :%w", err)
	}
	t.sourceIp = ip

	return nil
}

func (t *Target) setSourceIp(sourceIp netip.Addr) {
	t.sourceIp = sourceIp
}

// 设置TargetName (Private)
func (t *Target) setTargetName(name string) {
	t.targetname = name
}

// 查询端口状态
func (t *Target) getPortInfo(protocol int, port int) uint {
	return uint(t.PortStates[protocol][port])
}

// 设置主机名 (Private)
func (t *Target) setHostname(name string) {
	if name == "" {
		t.hostnames = ""
		return
	}
	bytes := []byte(name)
	for i, b := range bytes {
		if isAllowedHostnameChar(b) {
			continue
		}
		log.Printf("Illegal character(s) in hostname '%s' -- replacing with '*'\n", name)
		bytes[i] = '*'
	}
	t.hostnames = string(bytes)
}

// 设置端口状态
func (t *Target) setPortInfo(protocol int, port uint, state uint8) {
	t.PortStates[protocol][port] = state
}

// --- Helper Functions (Stateless, No Locking needed) ---

// 按类型返回Ipv4 or v6
func sockaddrToIP(sa unix.Sockaddr) (netip.Addr, error) {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(sa.Addr), nil
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(sa.Addr), nil
	default:
		return netip.Addr{}, errors.New("invalid Sockaddr")
	}
}

// 检查字符是否符合主机名
func isAllowedHostnameChar(b byte) bool {
	if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
		return true
	}
	switch b {
	case '.', '-', '=', ':', '_', '~', '*':
		return true
	}
	return false
}

func (t *Target) SetStateByPort(protocol int, port uint, state uint8, lookup []int) {
	t.PortStates[protocol][lookup[port]] = state
}
