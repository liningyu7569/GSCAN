package target

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// lcgCIDRGen 替代原来的 cidrGen
type lcgCIDRGen struct {
	start uint32
	end   uint32
	m     uint64 // 空间大小 (IP总数)
	a     uint64 // 乘数
	c     uint64 // 增量
	curr  uint64 // 当前的 X_n (0 到 m-1 的偏移量)
	step  uint64 // 已遍历的次数，用于控制结束
}

func newLCGCIDRGen(s string) (*lcgCIDRGen, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR is currently supported: %s", s)
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(v4) & mask
	end := start | ^mask

	// 计算网段内的 IP 总数
	m := uint64(end) - uint64(start) + 1

	// 满足 Hull-Dobell 定理的 LCG 参数 (当 m 为 2 的幂时)
	// a = 1664525 (满足 a ≡ 1 mod 4)
	// c = 1013904223 (满足 c 是奇数)
	a := uint64(1664525)
	c := uint64(1013904223)

	// 随机一个初始种子作为起点，这样每次扫描同一个网段的起始 IP 都不一样
	// 避免每次都从同一个 IP 开始扫描
	rand.Seed(time.Now().UnixNano())
	seed := uint64(rand.Int63n(int64(m)))

	return &lcgCIDRGen{
		start: start,
		end:   end,
		m:     m,
		a:     a,
		c:     c,
		curr:  seed,
		step:  0,
	}, nil
}

func (g *lcgCIDRGen) Next() net.IP {
	// 遍历次数达到 IP 总数时结束
	if g.step >= g.m {
		return nil
	}

	// 1. 根据当前偏移量计算实际 IP
	ipUint32 := g.start + uint32(g.curr)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipUint32)

	// 2. LCG 状态步进： X_{n+1} = (a * X_n + c) % m
	g.curr = (g.a*g.curr + g.c) % g.m
	g.step++

	return ip
}

func (g *lcgCIDRGen) Count() uint64 {
	return g.m
}
