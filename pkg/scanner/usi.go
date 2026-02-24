package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/target"
	"Going_Scan/pkg/ulit"
	"fmt"
	"github.com/google/gopacket/pcap"
	"math/rand/v2"
	"net/netip"
	"time"
)

type UltraScanInfo struct {
	IncompleteHosts []*HostScanStats

	SendChan chan SendTask
	RecvChan chan RecvEvent

	ScanDelay time.Duration

	handle *pcap.Handle

	IPMap          map[string]*HostScanStats
	CompletedHosts []*HostScanStats

	GStats *GlobalScanStats

	RecentEvents     [100]bool
	EventIndex       int
	GlobalTimeoutPct float64
}

// 初始化
func NewUSI(target []*target.Target) *UltraScanInfo {
	var ipmap = make(map[string]*HostScanStats)
	var incomhost = make([]*HostScanStats, len(target))
	for i, ip := range target {
		t := NewHSS(ip)
		ipmap[ip.TargetIpAddr().String()] = t
		incomhost[i] = t
	}
	// 获取配置中的 MaxRate
	maxRate := float64(conf.GlobalOps.MaxPacketSendRate)
	if maxRate <= 0 {
		maxRate = 0 // 无限
	}
	return &UltraScanInfo{
		CompletedHosts:  make([]*HostScanStats, 0),
		SendChan:        make(chan SendTask, 2048),
		RecvChan:        make(chan RecvEvent, 2048),
		IncompleteHosts: incomhost,
		IPMap:           ipmap,
		//	IncompleteHosts: wrapTarget(targets),
		ScanDelay: 0,
		GStats:    NewGSS(maxRate),
	}
}

func (usi *UltraScanInfo) Run() {

	// 1 ----------- 初始化Pcap、生产消费者线程-----------------

	//取得该组的目标地址并开启对于的Pcap
	sampleTarget := usi.IncompleteHosts[0].Target
	ifName := sampleTarget.Iface.Name
	srcIP := sampleTarget.SourceIpAddr()
	ip := ulit.NetipToStdIP(srcIP)
	//Pcap
	handle, err := OpenPcap(ifName, ip)
	if err != nil {
		fmt.Printf("Cannot open pcap :%v\n", err)
		return
	}
	defer handle.Close()
	injector := NewInjector(usi.SendChan, handle)
	//启动构建线程
	go injector.Run()

	receiver := NewReceiver(usi.RecvChan, handle)
	//启动接收线程
	go receiver.Run()

	lastTimeoutCheck := time.Now()
	timeoutInterval := 200 * time.Millisecond
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	//2、------------------主线程循环-------------------
	//从未完成列表开始循环每一个目标
	for len(usi.IncompleteHosts) > 0 {
		now := time.Now()
		//优先处理接收
	ReadLoop:
		for {
			select {
			//处理接收
			case evt := <-usi.RecvChan:
				usi.handleEvent(evt)
			default:
				break ReadLoop
			}
		}
		//宏观中控
		globalOK := usi.GlobalSendOK(now)
		anyGenerated := false
		//开始循环每一个HSS
		if globalOK {
			for i := 0; i < len(usi.IncompleteHosts); i++ {

				hss := usi.IncompleteHosts[i]
				//fmt.Println(hss.Target.TargetIpAddr())
				//检查此HSS的扫描进程是否完整完成
				//fmt.Println(len(hss.ProbesOutstanding))
				if !hss.FreshPortsLeft() && len(hss.ProbesOutstanding) == 0 && len(hss.RetryQueue) == 0 {
					usi.CompletedHosts = append(usi.CompletedHosts, hss)
					delete(usi.IPMap, hss.Target.TargetIpAddr().String())
					usi.removeHost(i)
					i--
					continue
				}
				//中控
				if hss.SendOK(now, usi.ScanDelay) {
					proto, port, isRetrans := hss.GetNextProbe()
					if port != -1 {

						decoyCount := conf.GlobalOps.NumDecoys

						totalPackets := decoyCount + 1
						if isRetrans {
							decoyCount = 0
						}

						//获取一个真实下标，0-len(诱饵)
						realIdx := 0
						if totalPackets > 1 {
							realIdx = getRandNum(0, totalPackets)
						}

						//获取序列
						seq := generateSeq()
						ack := uint32(0)
						flags := uint8(0x02)
						srcIP := hss.Target.SourceIpAddr()

						for j := 0; j < totalPackets; j++ {
							//在非真实IP时使用一个随机IP
							isReal := j == realIdx
							if !isReal {
								srcIP = getRandIp()
							} else {
								//仅当下标为真实时，那么获取目标真实IP
								srcIP = hss.Target.SourceIpAddr()
							}
							//写入数据
							task := SendTask{
								Target:   hss.Target,
								Protocol: proto,
								Port:     port,
								Seq:      seq,
								SrcIP:    srcIP,
								IsReal:   isReal,
								Ack:      ack,
								Flags:    flags,
							}
							select {
							case usi.SendChan <- task:
								fmt.Println("send to task")
								if isReal {
									fmt.Println("send to task for real")
									//仅记录真实的Probe
									hss.trackProbe(proto, port, seq, now)
									anyGenerated = true
									//网络负载+1

									usi.GStats.NumProbesActive++
									usi.GStats.ProbesSent++
								}

							default:
								if isReal {
									fmt.Println("xxx for log")
									hss.PushBackRetry(proto, port, seq)
									goto LoopEnd
								}

							}
						}
					}
				}
			}
		} else {
			time.Sleep(100 * time.Microsecond)
		}

	LoopEnd:
		//select {
		//case <-ticker.C:
		//	usi.processTimeouts()
		//default:
		//	if !anyGenerated {
		//		time.Sleep(100 * time.Millisecond)
		//	}
		//}
		if time.Since(lastTimeoutCheck) > timeoutInterval {
			//fmt.Println("time outs check")
			usi.processTimeouts()
			lastTimeoutCheck = time.Now()
		}
		if !anyGenerated {
			time.Sleep(5 * time.Millisecond)
		}

	}
	close(usi.SendChan)
}

//func (usi *UltraScanInfo) processTimeouts() {}

func (usi *UltraScanInfo) handleEvent(evt RecvEvent) {
	//fmt.Println("handle event")
	var probe *Probe
	var isPending bool
	var key string
	//1，检查当前的包是否为来自我们的扫描主机
	hss, exists := usi.IPMap[evt.SrcIP]
	if !exists {
		return
	}
	//fmt.Println("handle event 2")
	//查找对应此包的探针，通过协议+端口制作key->发包记录
	if evt.Protocol == ProtocolICMP {
		//对于ICMP，首先尝试UDP、TCP的查找回包
		keyUDP := makeProbeKey(ProtocolUDP, evt.SrcPort)
		if p, ok := hss.ProbesOutstanding[keyUDP]; ok {
			probe = p
			isPending = true
			key = keyUDP
		} else {
			// 尝试 2: 当作 TCP 探针查找 (Host Unreachable 等)
			keyTCP := makeProbeKey(ProtocolTCP, evt.SrcPort)
			if p, ok := hss.ProbesOutstanding[keyTCP]; ok {
				probe = p
				isPending = true
			}
			key = keyTCP
		}

	} else {
		keys := makeProbeKey(evt.Protocol, evt.SrcPort)
		probe, isPending = hss.ProbesOutstanding[keys]
		key = keys
	}

	if !isPending {

		//1，重复包，已经被处理
		//2，已经被超时移除
		//3，目标主机发送的无关包

		return
	}
	//3，TCP安全验证
	if evt.Protocol == ProtocolTCP {
		//基本扫描逻辑，在TCP中根据ACK验证是否匹配
		//对于RST包，有些OS回复Seq	/ACK并不标准
		//但对于基本SYN扫描，若出现不标准情况则选择丢弃，以防干扰
		//
		if !validateCookie(probe.Seq, evt.Ack) {

			return
		}
	}
	//fmt.Println("handle event 3")
	//-------------通过基本验证，确定为有效返回包-------------
	//宏观流控->成功返回包
	usi.recordSuccess()
	//判断窗口状态
	var portState uint8 = uint8(target.PortUnknown)

	switch evt.Protocol {
	case ProtocolTCP:
		// TCP 状态机
		if (evt.Flags & 0x04) != 0 { // RST Flag
			portState = uint8(target.PortClosed)
		} else if (evt.Flags & 0x12) == 0x12 { // SYN + ACK Flags
			portState = uint8(target.PortOpen)
		} else if (evt.Flags & 0x02) != 0 { // SYN only (极少见，Split Handshake)
			portState = uint8(target.PortOpen)
		}
		// 其他情况 (如只回 ACK) 在 SYN 扫描中通常视为 Unknown 或忽略

	case ProtocolUDP:
		// 如果真的收到了 UDP 数据包，那肯定是 Open
		portState = uint8(target.PortOpen)

	case ProtocolICMP:
		// 处理 UDP 扫描时收到的 ICMP 错误
		// 假设 Receiver 已经解析了 ICMP Type/Code
		// Type 3 (Dest Unreachable)
		if evt.ICMPType == 3 {
			if evt.ICMPCode == 3 {
				// Port Unreachable -> 端口关闭
				portState = uint8(target.PortClosed)
			} else if evt.ICMPCode == 1 || evt.ICMPCode == 2 || evt.ICMPCode == 9 || evt.ICMPCode == 10 || evt.ICMPCode == 13 {
				// Host Unreachable, Admin Prohibited 等 -> Filtered
				portState = uint8(target.PortFiltered)
			}
		}
	}
	//fmt.Println("handle event 4")
	//更新端口状态
	if portState != uint8(target.PortUnknown) {
		var lookup []int
		if evt.Protocol == ProtocolTCP {
			lookup = GlobalPorts.Maps[ProtocolTCP].Lookup
		}
		if evt.Protocol == ProtocolUDP {
			lookup = GlobalPorts.Maps[ProtocolUDP].Lookup
		}
		if evt.Protocol == ProtocolIP {
			lookup = GlobalPorts.Maps[ProtocolIP].Lookup
		}
		if lookup != nil {
			hss.Target.SetStateByPort(evt.Protocol, uint(evt.SrcPort), portState, lookup)
		}
		if hss.Target.Status != target.HostUp {
			hss.Target.Status = target.HostUp
		}
		//更新拥塞控制，微观
		rtt := evt.RecvTime.Sub(probe.SentTime)
		hss.UpdateCongestion(rtt)
		//减少网络负载
		if usi.GStats.NumProbesActive > 0 {
			usi.GStats.NumProbesActive--
		}
		//fmt.Println("handle event 6")
		delete(hss.ProbesOutstanding, key)
		//fmt.Println("handle event 7")
	}

}

func (usi *UltraScanInfo) removeHost(i int) {
	lastIdx := len(usi.IncompleteHosts) - 1

	usi.IncompleteHosts[i] = usi.IncompleteHosts[lastIdx]
	usi.IncompleteHosts[lastIdx] = nil
	usi.IncompleteHosts = usi.IncompleteHosts[:lastIdx]
}

func generateSeq() uint32 {
	//
	//
	//
	return uint32(time.Now().UnixNano())
}

func prepareDecoyList(srcip netip.Addr) ([]netip.Addr, int) {
	if conf.GlobalOps.NumDecoys > 0 {
		ind := getRandNum(0, conf.GlobalOps.NumDecoys)
		sendlist := make([]netip.Addr, conf.GlobalOps.NumDecoys)
		for i := 0; i < conf.GlobalOps.NumDecoys; i++ {
			if i == ind {
				sendlist[i] = srcip
				continue
			}
			ip := getRandIp()
			sendlist[i] = ip
		}
		return sendlist, ind
	} else {
		return []netip.Addr{srcip}, -1
	}

}

func getRandIp() netip.Addr {
	val := rand.Uint32()

	return netip.AddrFrom4([4]byte{
		uint8(val >> 24),
		uint8(val >> 16),
		uint8(val >> 8),
		uint8(val),
	})
}

func getRandNum(min, max int) int {
	return rand.N(max-min) + min
}

func validateCookie(sentSeq, recvAck uint32) bool {
	return recvAck == sentSeq+1
}

func (usi *UltraScanInfo) ultrascan_host_probe_update() {

}
func (usi *UltraScanInfo) GlobalSendOK(now time.Time) bool {
	// 1. 物理背压检查 (必须保留，防止内存溢出)
	if len(usi.RecvChan) > cap(usi.RecvChan)*8/10 {
		return false
	}
	if len(usi.SendChan) > cap(usi.SendChan)*8/10 {
		return false
	}

	// 2. 令牌桶限速 (用户明确指定的 --max-rate 必须遵守)
	if !usi.GStats.Limiter.AllowN(now, 1) {
		return false
	}

	// 3. 分级策略介入
	cfg := conf.GetTimingConfig()

	// 【T5 绿灯】如果是忽略拥塞模式，不再检查 Cwnd
	// 只要物理通道没满，就一直发
	if cfg.IgnoreCongestion {
		return true
	}

	// 4. 拥塞窗口检查
	// 【优化】如果当前活跃数还没达到 MinCwnd (比如 10)，无条件允许发送
	// 这保证了即使网络再差，也至少有 MinCwnd 个探针在跑，不会卡死
	if float64(usi.GStats.NumProbesActive) < cfg.MinCwnd {
		return true
	}

	if float64(usi.GStats.NumProbesActive) >= usi.GStats.Cwnd {
		return false
	}

	// 这个 < 2 的判断可以保留作为最后一道保底，
	// 但有了上面的 MinCwnd 检查，其实它已经不重要了
	if len(usi.IncompleteHosts) < 2 {
		return true
	}

	return true
}

func (usi *UltraScanInfo) updateGlobalCongestion(isGoodNews bool) {
	if isGoodNews {
		if usi.GStats.Cwnd < usi.GStats.Ssthresh {
			usi.GStats.Cwnd += 1.0
		} else {
			usi.GStats.Cwnd += 1.0 / usi.GStats.Cwnd
		}
	} else {

		usi.GStats.Ssthresh = usi.GStats.Cwnd / 2
		usi.GStats.Cwnd = usi.GStats.Cwnd / 2
		if usi.GStats.Cwnd < 10.0 {
			usi.GStats.Cwnd = 10.0
		}
	}
}

// 每次收包 (Good News)
func (usi *UltraScanInfo) recordSuccess() {
	usi.RecentEvents[usi.EventIndex%100] = false
	usi.EventIndex++
	usi.updateGlobalMetric()
}

// 每次判定超时 (Bad News)
func (usi *UltraScanInfo) recordTimeout() {
	usi.RecentEvents[usi.EventIndex%100] = true
	usi.EventIndex++
	usi.updateGlobalMetric()
}
func (usi *UltraScanInfo) updateGlobalMetric() {
	// 1. 获取分级配置
	cfg := conf.GetTimingConfig()

	timeoutCount := 0
	for _, isTimeout := range usi.RecentEvents {
		if isTimeout {
			timeoutCount++
		}
	}
	usi.GlobalTimeoutPct = float64(timeoutCount) / 100.0

	// --- T5 疯狗模式特判 ---
	if cfg.IgnoreCongestion {
		// T5 模式下，全局延迟强制归零，不允许增加
		usi.ScanDelay = 0
		// 全局窗口强制复位到初始值（或更高），防止因超时而萎缩
		if usi.GStats.Cwnd < cfg.InitialCwnd {
			usi.GStats.Cwnd = cfg.InitialCwnd
		}
		return // 无论超时多少，都不做任何惩罚
	}

	// --- 常规模式逻辑 ---

	// 如果最近 100 次网络交互中，超过 30% 都是超时
	if usi.GlobalTimeoutPct > 0.3 {
		// 1. 降低全局上限 (但受 MinCwnd 托底)
		newCwnd := usi.GStats.Cwnd * 0.8
		if newCwnd < cfg.MinCwnd {
			newCwnd = cfg.MinCwnd // 【托底】不能降得太低
		}
		usi.GStats.Cwnd = newCwnd

		// 2. 增加全局延迟 (但受 MaxScanDelay 封顶)
		usi.ScanDelay += 5 * time.Millisecond // 稍微温和一点，改 10 为 5
		if usi.ScanDelay > cfg.MaxScanDelay {
			usi.ScanDelay = cfg.MaxScanDelay // 【封顶】决不允许超过配置上限
		}

	} else if usi.GlobalTimeoutPct < 0.05 {
		// 网络很棒，提升全局上限
		usi.GStats.Cwnd += 1.0
		if usi.ScanDelay > 0 {
			usi.ScanDelay -= 1 * time.Millisecond
			// 再次防御性归零
			if usi.ScanDelay < 0 {
				usi.ScanDelay = 0
			}
		}
	}
}
