package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/target"
	"fmt"
	"strconv"
	"time"
)

type Probe struct {
	Proto    int
	Port     int
	Seq      uint32
	SentTime time.Time
	Retries  int
}

type HostScanStats struct {
	Target *target.Target

	NextTCPIndex int //扫描进度下标
	NextUDPIndex int
	NextIPIndex  int

	PriorityIter int //基准测试队列下标
	NormalIter   int
	ScannedPorts map[int]bool //已扫描端口

	// 拥塞控制
	Cwnd          float64       //拥塞窗口
	Ssthresh      float64       //慢启动阈值
	Srtt          time.Duration //平滑RTT
	RttVar        time.Duration //RTT波动
	Timeout       time.Duration //当前超时次数
	LastSend      time.Time     //上一次发包时间
	RetryCount    int           //主机总重试次数
	HostScanDelay time.Duration

	ProbesOutstanding map[string]*Probe

	IsCompleted bool
	//重传列表
	RetryQueue []*Probe
}

// 初始化
func NewHSS(t *target.Target) *HostScanStats {

	cfg := conf.GetTimingConfig()

	return &HostScanStats{
		Target:       t,
		NextTCPIndex: 0,
		NextUDPIndex: 0,

		Cwnd:     cfg.InitialCwnd,
		Ssthresh: 75.0,       // 慢启动阈值
		Timeout:  cfg.MaxRTO, // 初始超时设为最大值或默认值

		ProbesOutstanding: make(map[string]*Probe),
		RetryQueue:        make([]*Probe, 0),

		ScannedPorts: make(map[int]bool),
		PriorityIter: 0,
	}
}

// FreshPortsLeft 进度下标
func (hss *HostScanStats) FreshPortsLeft() bool {
	if GlobalPorts.Maps[ProtocolTCP] != nil {
		//	fmt.Println("Index:", hss.NextTCPIndex)
		//	fmt.Print("Count:", GlobalPorts.Maps[ProtocolTCP].Count())

		if hss.NextTCPIndex < GlobalPorts.Maps[ProtocolTCP].Count() {
			return true
		}
	}
	if GlobalPorts.Maps[ProtocolUDP] != nil {
		if hss.NextUDPIndex < GlobalPorts.Maps[ProtocolUDP].Count() {
			return true
		}
	}
	if GlobalPorts.Maps[ProtocolIP] != nil {
		if hss.NextIPIndex < GlobalPorts.Maps[ProtocolIP].Count() {
			return true
		}
	}
	return false
}

// 获取当前扫描进度下标
func (hss *HostScanStats) GetNextProbe() (int, int, bool) {
	//优先处理重传队列
	if len(hss.RetryQueue) > 0 {
		fmt.Println("执行重传")
		probe := hss.RetryQueue[0]
		hss.RetryQueue = hss.RetryQueue[1:]
		return probe.Proto, probe.Port, true
	}
	if GlobalPorts.Maps[ProtocolTCP] != nil {
		for hss.PriorityIter < len(TopPorts) {
			port := TopPorts[hss.PriorityIter]
			hss.PriorityIter++

			if GlobalPorts.Maps[ProtocolTCP].IsScanned(port) {
				hss.ScannedPorts[port] = true
				return ProtocolTCP, port, false
			}
		}
	}
	if GlobalPorts.Maps[ProtocolTCP] != nil && hss.NextTCPIndex < GlobalPorts.Maps[ProtocolTCP].Count() {
		for {

			idx := hss.NextTCPIndex

			port := GlobalPorts.Maps[ProtocolTCP].GetPort(idx)

			//hss.NextTCPIndex++
			if hss.ScannedPorts[port] {
				//continue
			}
			return ProtocolTCP, port, false
		}
	}

	if GlobalPorts.Maps[ProtocolUDP] != nil && hss.NextUDPIndex < GlobalPorts.Maps[ProtocolUDP].Count() {
		idx := hss.NextUDPIndex
		port := GlobalPorts.Maps[ProtocolUDP].GetPort(idx)
		//hss.NextUDPIndex++
		return ProtocolUDP, port, false
	}

	return -1, -1, false
}

func (hss *HostScanStats) trackProbe(proto int, port int, seq uint32, now time.Time) {
	hss.LastSend = now
	//生成端口+协议组成的key
	key := makeProbeKey(proto, port)

	if existingProbe, exists := hss.ProbesOutstanding[key]; exists {
		existingProbe.SentTime = now
		existingProbe.Retries++
		fmt.Println("重传+1")
		existingProbe.Seq = seq
		return
	}

	//更新扫描进度
	if proto == ProtocolTCP {
		hss.NextTCPIndex++
	} else if proto == ProtocolUDP {
		hss.NextUDPIndex++
	}

	newProbe := &Probe{
		Proto:    proto,
		Port:     port,
		Seq:      seq,
		SentTime: now,
		Retries:  0,
	}
	hss.ProbesOutstanding[key] = newProbe
}

func makeProbeKey(proto, port int) string {
	return strconv.Itoa(proto) + ":" + strconv.Itoa(port)
}
func (hss *HostScanStats) SendOK(now time.Time, globalDelay time.Duration) bool {
	// ... 前面的 InFlight 检查不变 ...

	// 计算生效延迟
	effectiveDelay := globalDelay
	if hss.HostScanDelay > effectiveDelay {
		effectiveDelay = hss.HostScanDelay
	}

	// 【新增】再次确认生效延迟不超过配置上限
	// 因为 globalDelay 是从 USI 传进来的，虽然我们在 USI 里做了限制，
	// 但在这里再锁一道保险更稳妥。
	cfg := conf.GetTimingConfig()
	if effectiveDelay > cfg.MaxScanDelay {
		effectiveDelay = cfg.MaxScanDelay
	}

	if now.Sub(hss.LastSend) < effectiveDelay {
		return false
	}

	return true
}

// 重插入重传队首
func (hss *HostScanStats) PushBackRetry(proto int, port int, seq uint32) {

	p := &Probe{
		Proto: proto,
		Port:  port,
		Seq:   seq,
	}
	hss.RetryQueue = append([]*Probe{p}, hss.RetryQueue...)

}
