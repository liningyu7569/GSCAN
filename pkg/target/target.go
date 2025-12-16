package target

import (
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
	target_ip, source_ip, nexthope_ip   netip.Addr
	targetSock, sourceSock, nextHopSock unix.Sockaddr
	// --- 链路层信息 (L2 Scanning 需要) ---
	// 用于存储解析到的 MAC 地址或网关 MAC
	mac        net.HardwareAddr
	nextHopMAC net.HardwareAddr // 如果是外网目标，这里存网关 MAC
	iface      *net.Interface   // 出口网卡

	// --- 状态信息 (并发读写) ---
	// 必须使用 RWMutex 保护，因为扫描协程会并发写入 Port 结果
	mu         sync.RWMutex
	status     HostStatus
	hostnames  string
	targetname string
	//TTL
	distance int8
	//TTL估计方式
	distance_calculation_method int8
	//存储结果
	FPR         []string
	osscan_flag int8

	// 端口存储
	// map[uint16]*PortInfo 用于稀疏扫描
	// 如果是全端口扫描，建议优化为 Slice 或 BitSet
	ports map[uint16]*PortInfo

	// OS 探测结果 (预留)
	osFingerprint string
}

// NewTarget 工厂函数
// 工厂函数返回的是新对象，尚未被共享，因此不需要加锁
func NewTarget(ipStr string) (*Target, error) {
	// 解析 IP (支持 IPv4/IPv6)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target IP: %w", err)
	}

	return &Target{
		target_ip: addr,
		status:    HostUnknown,
		ports:     make(map[uint16]*PortInfo),
	}, nil
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
	t.target_ip = ip

	return nil
}

// 返回源Sock (Private)
func (t *Target) sourceSockAddr() unix.Sockaddr {
	return t.sourceSock
}

// 设置源Sock (Private)
func (t *Target) setSourceSockAddr(sa unix.Sockaddr) error {
	t.sourceSock = sa
	ip, err := sockaddrToIP(sa)
	if err != nil {
		return fmt.Errorf("invalid Source_sockaddr :%w", err)
	}
	t.source_ip = ip

	return nil
}

// 设置TargetName (Private)
func (t *Target) setTargetName(name string) {
	t.targetname = name
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
