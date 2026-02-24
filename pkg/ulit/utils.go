package ulit

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
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
