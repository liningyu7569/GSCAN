package target

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Iterator interface {
	Next() net.IP
	Count() uint64
}

type Container struct {
	generator  []Generator     //IP解析器接口
	currIndex  int             //解析IP下标
	excludeMap map[string]bool //是否为被排除的IP
}

// 获取下一个IP的接口
type Generator interface {
	Next() net.IP
	Count() uint64
}

// IP初始化
func NewContainer(inputs []string, exclides []string) (Iterator, error) {
	c := &Container{
		generator:  make([]Generator, 0),
		excludeMap: make(map[string]bool),
	}
	if len(exclides) > 0 {
		for _, excItem := range exclides { //
			//
			if excItem == "" {
				continue
			}
			//
			c.excludeMap[excItem] = true
		}
	}
	//初始化输入IP
	for _, input := range inputs {
		//执行选择解析函数
		gen, err := selectStrategy(input)
		if err != nil {
			return nil, err
		}
		//存储返回的接口
		c.generator = append(c.generator, gen)
	}
	return c, nil
}

func (c *Container) Next() net.IP {
	for {
		//解析结束返回nil
		if c.currIndex >= len(c.generator) {
			return nil
		}
		//获取对应解析的IP
		ip := c.generator[c.currIndex].Next()
		if ip == nil {
			c.currIndex++
			continue
		}
		//若为排除IP则继续找下一个
		if c.excludeMap[ip.String()] {
			continue
		}
		return ip
	}
}

func (c *Container) Count() uint64 {
	var total uint64
	for _, gen := range c.generator {
		if gen == nil {
			continue
		}
		total += gen.Count()
	}

	if len(c.excludeMap) == 0 {
		return total
	}

	// 粗粒度扣减：仅扣除显式排除的单个 IP。
	for exclude := range c.excludeMap {
		if net.ParseIP(exclude) != nil && total > 0 {
			total--
		}
	}

	return total
}

// 选择解析函数
func selectStrategy(input string) (Generator, error) {
	if strings.Contains(input, "/") {
		return newLCGCIDRGen(input)
	} else if strings.Contains(input, "-") {
		return newLCGRangeGen(input)
	} else {
		return newSingleGen(input)
	}

}

// Single IP
// 简单IP
type singleGen struct {
	ip   net.IP
	done bool
}

func newSingleGen(s string) (*singleGen, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	return &singleGen{ip: ip, done: false}, nil
}
func (g *singleGen) Next() net.IP {
	if g.done {
		return nil
	}
	g.done = true
	return g.ip
}

func (g *singleGen) Count() uint64 {
	return 1
}

// 范围IP
type rangeGen struct {
	start, end, curr uint32
}

func newRangeGen(s string) (*rangeGen, error) {
	parts := strings.Split(s, "-")
	//获取首位IP
	startIP := net.ParseIP(parts[0])
	if startIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	//获取尾部IP
	endIP := net.ParseIP(parts[1])
	//构建尾部IP
	if endIP == nil {
		lastByte, _ := strconv.Atoi(parts[1])
		v4 := startIP.To4()
		endIP = net.IPv4(v4[0], v4[1], v4[2], byte(lastByte))
	}
	//存储首部和尾部
	start := binary.BigEndian.Uint32(startIP.To4())
	end := binary.BigEndian.Uint32(endIP.To4())
	return &rangeGen{start: start, end: end, curr: start}, nil
}
func (g *rangeGen) Next() net.IP {
	if g.curr > g.end {
		return nil
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, g.curr)
	g.curr++
	return ip
}

func (g *rangeGen) Count() uint64 {
	return uint64(g.end-g.start) + 1
}

type cidrGen struct {
	start uint32
	end   uint32
	curr  uint32
}

func newCIDRGen(s string) (*cidrGen, error) {
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

	return &cidrGen{
		start: start,
		end:   end,
		curr:  start,
	}, nil
}

func (g *cidrGen) Next() net.IP {
	if g.curr > g.end {
		return nil
	}

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, g.curr)
	g.curr++
	return ip
}

func (g *cidrGen) Count() uint64 {
	return uint64(g.end-g.start) + 1
}
