package util

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"strings"
	"unicode"
)

// 使用netip.Addr创建unix.Sockaddr
func NetipToSockaddr(addr netip.Addr, port int) (unix.Sockaddr, error) {
	addr = addr.Unmap()
	if addr.Is4() {
		sa := &unix.SockaddrInet4{
			Port: port,
		}
		sa.Addr = addr.As4()
		return sa, nil
	}
	if addr.Is6() {
		sa := &unix.SockaddrInet6{
			Port: port,
		}
		sa.Addr = addr.As16()
		return sa, nil
	}
	return nil, fmt.Errorf("not a valid IP address for %s", addr.String())
}

// 将net.ip转换为netip.addr
func StdIPToNetip(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("not a valid IP address for %s", ip.String())
	}

	return addr.Unmap(), nil
}

func NetipToStdIP(addr netip.Addr) net.IP {
	return net.IP(addr.AsSlice())
}

// IPToUint32 将 net.IP 转换为 uint32 (大端序)
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP 将 uint32 转回 net.IP
func Uint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// CleanBanner 将不可见字符转换为转义符
func CleanBanner(banner string) string {
	if banner == "" {
		return ""
	}
	// 简单粗暴：只保留可见字符或常用空白符
	res := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return -1 // 丢弃
	}, banner)
	return strings.TrimSpace(res)
}
