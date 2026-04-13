package conf

import (
	"Going_Scan/pkg/target"
	"fmt"
	"golang.org/x/sys/unix"
	"strings"
)

type GlobalConfig struct {
	Family int

	InputS []string

	Synscan     bool // -s
	Connectscan bool // --connect
	Udpscan     bool // -U
	Pingtype    bool
	Oscan       bool // -O
	Servicescan bool // -V
	Idlescan    bool
	IdleProxy   string // --zombie
	Ackscan     bool   // -A
	Windowscan  bool   // -W
	Ipprotscan  bool   // -Y (protocol)

	TimingLevel       int     // -T
	MinPacketSendRate float32 // --min-rate
	MaxPacketSendRate float32 // --max-rate
	MinParallelism    int     // --min-parallelism
	MaxParallelism    int     // --max-parallelism
	MaxRTTTimeout     int     // --max-rtt-timeout
	HostTimeout       int     // --host-timeout
	MaxRetries        int     // --max-retries

	RandomizeHosts bool // --randomize-hosts
	RandomizePort  bool // (内部逻辑或 --randomize-ports)
	FastScan       bool // -F
	TopPort        int  // --top-ports

	FragScan           bool // -f
	BadSum             bool // --badsum
	DataLength         int  // --data-length
	DefeatRSTRateLimit bool // --defeat-rst-ratelimit

	SpoofIP string // -S
	Device  string // -e

	SourceSock  unix.Sockaddr
	SpoolSource bool
	MagicPort   int // 内部逻辑使用
	TTL         int // --ttl
	ProxyChain  string

	PortStr    string // -p
	ExcludeStr string // --exclude

	SourcePort int // -g / --source-port

	NumDecoys int // -D

	SkipHostDiscovery bool   //Pn
	OutputFile        string //output file path
	OutputFormat      string
	IsOutputFile      bool
	UAMDBPath         string
}

func (g *GlobalConfig) Af() int {
	return g.Family
}

var GlobalOps = &GlobalConfig{
	InputS:            make([]string, 0),
	ExcludeStr:        "",
	SkipHostDiscovery: false,
}

func (g *GlobalConfig) GetTargetIterator() (target.Iterator, error) {
	if len(g.InputS) == 0 {
		return nil, fmt.Errorf("no target specified")
	}
	var excludes []string
	// 只有当字符串不为空时才分割
	if g.ExcludeStr != "" {
		excludes = strings.Split(g.ExcludeStr, ",")
	}
	return target.NewContainer(g.InputS, excludes, g.RandomizeHosts)
}
func (g *GlobalConfig) TCPScan() bool {
	return g.Ackscan || g.Synscan || g.Connectscan || g.Idlescan || g.Windowscan
}
func (g *GlobalConfig) UDPScan() bool {
	return g.Udpscan
}
func (g *GlobalConfig) Ping() bool {
	return g.Pingtype
}
