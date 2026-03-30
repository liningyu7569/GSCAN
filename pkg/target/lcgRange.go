package target

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// lcgRangeGen 替代原来的 rangeGen
type lcgRangeGen struct {
	start uint32
	end   uint32
	count uint32 // 实际的 IP 数量 N
	m     uint32 // 扩容后 2 的幂次 M
	a     uint32 // 乘数
	c     uint32 // 增量
	curr  uint32 // 当前的 X_n (0 到 m-1 的偏移量)
	step  uint32 // 已经成功输出的 IP 数量，用于控制结束
}

func newLCGRangeGen(s string) (*lcgRangeGen, error) {
	parts := strings.Split(s, "-")
	startIP := net.ParseIP(parts[0])
	if startIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}

	endIP := net.ParseIP(parts[1])
	if endIP == nil {
		lastByte, _ := strconv.Atoi(parts[1])
		v4 := startIP.To4()
		endIP = net.IPv4(v4[0], v4[1], v4[2], byte(lastByte))
	}

	start := binary.BigEndian.Uint32(startIP.To4())
	end := binary.BigEndian.Uint32(endIP.To4())

	if start > end {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// 1. 计算真实的 IP 数量 N
	count := end - start + 1

	// 2. 找到大于等于 count 的最小的 2 的幂 M
	var m uint32
	if count == 1 {
		m = 1
	} else {
		// bits.Len32(count - 1) 会返回最高有效位的索引，移位后即为最小的 2 的幂
		m = 1 << bits.Len32(count-1)
	}

	// 满足 Hull-Dobell 定理的经典 LCG 参数
	// 只要 m 是 2 的幂，这套 a 和 c 就能保证满周期
	a := uint32(1664525)
	c := uint32(1013904223)

	rand.Seed(time.Now().UnixNano())
	seed := uint32(rand.Int31n(int32(m)))

	return &lcgRangeGen{
		start: start,
		end:   end,
		count: count,
		m:     m,
		a:     a,
		c:     c,
		curr:  seed,
		step:  0,
	}, nil
}

func (g *lcgRangeGen) Next() net.IP {
	// 如果已经输出了足量的真实 IP，则结束
	if g.step >= g.count {
		return nil
	}

	var offset uint32

	// Cycle-Walking (周期漫步/拒绝采样)
	for {
		offset = g.curr
		// LCG 状态步进
		g.curr = (g.a*g.curr + g.c) % g.m

		// 如果偏移量落在真实的 count 范围内，就是我们要找的有效 IP，跳出循环
		if offset < g.count {
			break
		}
		// 如果 offset >= count，说明落在为了凑 2 的幂而多出来的虚假空间里，继续下一次 LCG 计算
	}

	g.step++

	ipUint32 := g.start + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipUint32)

	return ip
}

func (g *lcgRangeGen) Count() uint64 {
	return uint64(g.count)
}
