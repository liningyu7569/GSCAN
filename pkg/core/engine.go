package core

import (
	"Going_Scan/pkg/util"
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/metrics"
	"Going_Scan/pkg/queue"
	"github.com/google/gopacket/pcap"
)

// --- 测试功能专用变量 (用完可注释) ---
var testOpenPorts sync.Map

// ------------------------------------

const MaxCWNDLimit = 20000

// 强制扩容至 128 字节，防止 TCP Options 注入时发生物理越界
var taskBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 128)
		return &buf
	},
}

// 实例化全局 L7 任务转接队列与分片指标池
var (
	GlobalResultBuffer  = queue.NewLockFreeRingBuffer[queue.ScanResult](65536)
	MetricPacketsSent   metrics.ShardedMetrics
	MetricPacketsMatch  metrics.ShardedMetrics
	MetricDispatchDrops metrics.ShardedMetrics
	MetricFiltered      metrics.ShardedMetrics
	MetricOpenPorts     metrics.ShardedMetrics
	MetricTasksDone     metrics.ShardedMetrics
)

type Engine struct {
	Targets         []uint64
	Channels        []chan PacketTensor
	Tokens          chan struct{}
	FreeIDs         chan uint16
	sendTokens      chan struct{}
	sendRate        float64
	srtt            int64
	rto             int64
	currentCapacity int32
	activeProbes    int32
	pcapHandle      *pcap.Handle
}

func NewEngine(handle *pcap.Handle) *Engine {
	initialCWND := deriveInitialCWND()
	sendRate := effectiveSendRate()
	if conf.GlobalOps.MinParallelism <= 0 || conf.GlobalOps.MinParallelism > initialCWND {
		conf.GlobalOps.MinParallelism = initialCWND
	}
	if conf.GlobalOps.MaxParallelism <= 0 || conf.GlobalOps.MaxParallelism > MaxCWNDLimit {
		conf.GlobalOps.MaxParallelism = MaxCWNDLimit
	}
	initHDFilter()
	GlobalResultBuffer = queue.NewLockFreeRingBuffer[queue.ScanResult](65536)
	MetricPacketsSent = metrics.ShardedMetrics{}
	MetricPacketsMatch = metrics.ShardedMetrics{}
	MetricDispatchDrops = metrics.ShardedMetrics{}
	MetricFiltered = metrics.ShardedMetrics{}
	MetricOpenPorts = metrics.ShardedMetrics{}
	MetricTasksDone = metrics.ShardedMetrics{}

	e := &Engine{
		Targets:         make([]uint64, MaxCWNDLimit),
		Channels:        make([]chan PacketTensor, MaxCWNDLimit),
		Tokens:          make(chan struct{}, MaxCWNDLimit),
		FreeIDs:         make(chan uint16, MaxCWNDLimit),
		sendRate:        sendRate,
		srtt:            100,
		rto:             int64(conf.GlobalOps.MaxRTTTimeout),
		currentCapacity: int32(initialCWND),
		pcapHandle:      handle,
	}
	if sendRate > 0 {
		e.sendTokens = make(chan struct{}, sendBurstCapacity(sendRate))
		e.sendTokens <- struct{}{}
	}

	for i := uint16(0); i < uint16(MaxCWNDLimit); i++ {
		e.Channels[i] = make(chan PacketTensor, 1)
		e.FreeIDs <- i
	}

	for i := 0; i < initialCWND; i++ {
		e.Tokens <- struct{}{}
	}
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		for range ticker.C {
			// 将分片缓存行的数据聚合，覆写至旧版 GlobalMetrics
			atomic.StoreInt64(&GlobalMetrics.PacketsSent, MetricPacketsSent.Read())
			atomic.StoreInt64(&GlobalMetrics.PacketsMatched, MetricPacketsMatch.Read())
			atomic.StoreInt64(&GlobalMetrics.DispatchDrops, MetricDispatchDrops.Read())
			atomic.StoreInt64(&GlobalMetrics.Filtered, MetricFiltered.Read())
			atomic.StoreInt64(&GlobalMetrics.OpenPorts, MetricOpenPorts.Read())
			atomic.StoreInt64(&GlobalMetrics.TasksDone, MetricTasksDone.Read())
		}
	}()
	return e
}

func (e *Engine) Run(ctx context.Context, generator *TaskGenerator) {
	var wg sync.WaitGroup
	//var exhausted = false

	go e.runSendPacer(ctx)
	// 启动 L4 Pcap 物理接收流
	go e.RunDispatcher(ctx)
	// 启动 L7 RingBuffer 消费流
	go e.RunL7Dispatcher(ctx)

	fmt.Println("[Engine] 发射引擎点火，开始消费 EmissionTask...")

Loop:
	for {
		select {
		case <-ctx.Done():
			fmt.Println("[Engine] 收到上下文取消信号，停止下发新任务...")
			break Loop
		default:
		}

		tasks, isDone := generator.GenerateBatch()

		if isDone {
			//exhausted = true
			// 关键点：如果任务耗尽且没有正在飞行的探针，说明真的结束了
			if atomic.LoadInt32(&e.activeProbes) == 0 {
				fmt.Println("[Engine] 所有任务分发完毕，且无在途探针，准备退出...")
				break Loop
			}
			// 还有探针在飞，或者蓄水池可能随时被 Dispatcher 填入新 IP
			// 此时引擎进入低功耗休眠，等待回包触发蓄水池
			time.Sleep(10 * time.Millisecond)
			continue
		}

		//if len(tasks) == 0 {
		//	break Loop
		//}

		for _, task := range tasks {
			select {
			case <-ctx.Done():
				break Loop
			case <-e.Tokens:
			}
			channelID := <-e.FreeIDs
			wg.Add(1)
			atomic.AddInt32(&e.activeProbes, 1)

			go func(id uint16, t EmissionTask) {
				defer wg.Done()
				e.LaunchProbe(ctx, id, t)
				e.FreeIDs <- id
				e.Tokens <- struct{}{}
				atomic.AddInt32(&e.activeProbes, -1)
			}(channelID, task)
		}
	}

	fmt.Println("[Engine] 等待飞行中的探针返回或超时...")
	wg.Wait()
	tailWait := atomic.LoadInt64(&e.rto) * 2
	if tailWait < 1000 {
		tailWait = 1000 // 最小保底等待 1 秒
	}
	time.Sleep(time.Duration(tailWait) * time.Millisecond)
	//for j := range TestIP {
	//	fmt.Printf(TestIP[j].String() + " - ")
	//}
	// --- 测试功能：输出所有开放端口 (用完可注释) ---
	fmt.Println("\n====== [Test] Discovered Open Ports ======")
	testOpenPorts.Range(func(key, value interface{}) bool {
		fmt.Printf("=> %s\n", key)
		return true // 继续遍历
	})
	fmt.Println("==========================================")
	// ----------------------------------------------
	fmt.Println("[Engine] 所有探测任务已安全结束。")
	e.printReport()
}

func (e *Engine) LaunchProbe(ctx context.Context, channelID uint16, task EmissionTask) {
	drainTensorChannel(e.Channels[channelID])
	validationCode := (uint64(task.TargetIP) << 16) | uint64(task.TargetPort)
	atomic.StoreUint64(&e.Targets[channelID], validationCode)
	defer atomic.StoreUint64(&e.Targets[channelID], 0)
	defer MetricTasksDone.Add(uint64(channelID), 1)

	routeMeta := GlobalRouteCache[task.RouteID]
	maxRetries := conf.GlobalOps.MaxRetries

	for attempt := 0; attempt <= maxRetries; attempt++ {
		drainTensorChannel(e.Channels[channelID])
		if err := e.waitSendTurn(ctx); err != nil {
			return
		}

		bufPtr := taskBufferPool.Get().(*[]byte)
		packetLen, err := BuildIntoBuffer(bufPtr, task, channelID, routeMeta)

		if err == nil {
			err = e.pcapHandle.WritePacketData((*bufPtr)[:packetLen])
			if err == nil {
				MetricPacketsSent.Add(uint64(channelID), 1)
			}
		}
		taskBufferPool.Put(bufPtr)

		if err != nil {
			fmt.Printf("[Engine] 发包失败 target=%d:%d attempt=%d err=%v\n", task.TargetIP, task.TargetPort, attempt, err)
			break
		}

		timerStartTime := time.Now()
		currentRTO := atomic.LoadInt64(&e.rto)
		if currentRTO <= 0 {
			currentRTO = int64(conf.GlobalOps.MaxRTTTimeout)
		}
		timeout := currentRTO * int64(1<<attempt)
		if timeout > int64(conf.GlobalOps.MaxRTTTimeout) {
			timeout = int64(conf.GlobalOps.MaxRTTTimeout)
		}
		if timeout < 50 {
			timeout = 50
		}

		timer := time.NewTimer(time.Duration(timeout) * time.Millisecond)
		var resultTensor PacketTensor

		select {
		case resultTensor = <-e.Channels[channelID]:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			resultTensor = TensorTimeout
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}

		if resultTensor == TensorTimeout {
			MetricFiltered.Add(uint64(channelID), 1)
			if conf.GlobalOps.TimingLevel <= 3 {
				e.decreaseCWND()
			}
			continue
		} else {
			e.increaseCWND()
			rttMilliseconds := int64(time.Since(timerStartTime).Milliseconds())
			e.updateRTO(rttMilliseconds)

			if task.IsHostDiscovery {
				if resultTensor.IsHostAlive(task.Protocol) {
					if markAlive(task.TargetIP) {
						ipStr := util.Uint32ToIP(task.TargetIP).String()
						fmt.Printf(ipStr + " is alive\n")
						for !HDReservoir.Push(task.TargetIP) {
							if ctx.Err() != nil {
								return
							}
							runtime.Gosched()
						}
					}
				}
				break
			}

			isOpen := false
			if task.Protocol == syscall.IPPROTO_TCP && resultTensor.IsTCPStateOpen() {
				isOpen = true
			} else if task.Protocol == syscall.IPPROTO_UDP && resultTensor.DecodeProtocol() == syscall.IPPROTO_UDP {
				isOpen = true
			}

			if isOpen {
				MetricOpenPorts.Add(uint64(channelID), 1)

				// --- 测试功能：记录开放端口 (用完可注释) ---
				ipStr := util.Uint32ToIP(task.TargetIP).String()
				testOpenPorts.Store(fmt.Sprintf("%s:%d", ipStr, task.TargetPort), struct{}{})
				// ------------------------------------------
				res := queue.ScanResult{
					IP:       task.TargetIP,
					Port:     task.TargetPort,
					Protocol: task.Protocol,
				}

				// 无锁压入环形缓冲区，遇满自旋让出 CPU，绝不阻塞发包层
				for !GlobalResultBuffer.Push(res) {
					if ctx.Err() != nil {
						return
					}
					runtime.Gosched()
				}
			}
			break
		}
	}
}

// 保持你当前的 O(1) 物理拦截版本
func (e *Engine) RunDispatcher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packetData, _, err := e.pcapHandle.ZeroCopyReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if len(packetData) < 34 {
			continue
		}
		if packetData[12] != 0x08 || packetData[13] != 0x00 {
			continue
		}

		ihl := packetData[14] & 0x0F
		ipHeaderLen := int(ihl) * 4
		if len(packetData) < 14+ipHeaderLen+4 {
			continue
		}

		ipProtocol := packetData[23]
		var channelID uint16
		var packetSrcPort uint16
		var packetSrcIP uint32
		var ok bool

		switch ipProtocol {
		case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
			channelID, ok = decodeChannelPort(binary.BigEndian.Uint16(packetData[14+ipHeaderLen+2 : 14+ipHeaderLen+4]))
			if !ok {
				continue
			}
			packetSrcPort = binary.BigEndian.Uint16(packetData[14+ipHeaderLen : 14+ipHeaderLen+2])
			packetSrcIP = binary.BigEndian.Uint32(packetData[26:30])
		case 1:
			channelID, packetSrcIP, packetSrcPort, ok = decodeICMPMatch(packetData, ipHeaderLen)
			if !ok {
				continue
			}
		default:
			continue
		}

		if int(channelID) >= MaxCWNDLimit {
			continue
		}

		actualTarget := (uint64(packetSrcIP) << 16) | uint64(packetSrcPort)

		expectedTarget := atomic.LoadUint64(&e.Targets[channelID])
		if actualTarget != expectedTarget {
			continue
		}

		ipv4Header := packetData[14 : 14+ipHeaderLen]
		transportHeader := packetData[14+ipHeaderLen:]
		tensor := ExtractTensor(ipv4Header, transportHeader)

		select {
		case e.Channels[channelID] <- tensor:
			MetricPacketsMatch.Add(uint64(channelID), 1)
		default:
			MetricDispatchDrops.Add(uint64(channelID), 1)
		}
	}
}

// RunL7Dispatcher L7 侧唯一消费者。死循环抽水机。
func (e *Engine) RunL7Dispatcher(ctx context.Context) {
	var result queue.ScanResult
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if GlobalResultBuffer.Pop(&result) {
				openResult := ScanResult{
					IP:       result.IP,
					Port:     result.Port,
					Protocol: result.Protocol,
					State:    "Open",
				}
				select {
				case ResultStream <- openResult:
				default:
					printResult(openResult)
				}
			} else {
				// 缓冲区空，让出时间片防止空转
				time.Sleep(1 * time.Millisecond)
			}
		}
	}
}

func (e *Engine) increaseCWND() {
	current := atomic.LoadInt32(&e.currentCapacity)
	if current < int32(conf.GlobalOps.MaxParallelism) {
		select {
		case e.Tokens <- struct{}{}:
			atomic.AddInt32(&e.currentCapacity, 1)
		default:
		}
	}
}

func (e *Engine) decreaseCWND() {
	current := atomic.LoadInt32(&e.currentCapacity)
	minCWND := int32(conf.GlobalOps.MinParallelism)
	dropCount := current / 2
	if current-dropCount < minCWND {
		dropCount = current - minCWND
	}
	if dropCount <= 0 {
		return
	}
	for i := int32(0); i < dropCount; i++ {
		select {
		case <-e.Tokens:
			atomic.AddInt32(&e.currentCapacity, -1)
		default:
			return
		}
	}
}

func (e *Engine) updateRTO(rtt int64) {
	if rtt <= 0 {
		rtt = 1
	}
	srtt := atomic.LoadInt64(&e.srtt)
	newSRTT := (srtt*7 + rtt) / 8
	if newSRTT == 0 {
		newSRTT = rtt
	}
	atomic.StoreInt64(&e.srtt, newSRTT)
	newRTO := newSRTT * 3
	maxLimit := int64(conf.GlobalOps.MaxRTTTimeout)
	if newRTO > maxLimit {
		newRTO = maxLimit
	}
	if newRTO < 50 {
		newRTO = 50
	}
	atomic.StoreInt64(&e.rto, newRTO)
}

func deriveInitialCWND() int {
	initialCWND := conf.GlobalOps.MinParallelism
	if initialCWND <= 0 {
		initialCWND = 100
	}

	if conf.GlobalOps.MaxParallelism > 0 && initialCWND > conf.GlobalOps.MaxParallelism {
		initialCWND = conf.GlobalOps.MaxParallelism
	}

	rate := effectiveSendRate()
	if rate > 0 {
		timeoutMs := conf.GlobalOps.MaxRTTTimeout
		if timeoutMs <= 0 {
			timeoutMs = 1000
		}

		suggested := int(rate * float64(timeoutMs) / 1000.0)
		if suggested < 64 {
			suggested = 64
		}
		if conf.GlobalOps.MaxParallelism > 0 && suggested > conf.GlobalOps.MaxParallelism {
			suggested = conf.GlobalOps.MaxParallelism
		}
		if initialCWND > suggested {
			initialCWND = suggested
		}
	}

	if initialCWND > MaxCWNDLimit {
		initialCWND = MaxCWNDLimit
	}

	return initialCWND
}

func effectiveSendRate() float64 {
	if conf.GlobalOps.MaxPacketSendRate > 0 {
		return float64(conf.GlobalOps.MaxPacketSendRate)
	}
	if conf.GlobalOps.MinPacketSendRate > 0 {
		return float64(conf.GlobalOps.MinPacketSendRate)
	}
	return 0
}

func sendBurstCapacity(rate float64) int {
	capacity := int(rate / 20)
	if capacity < 1 {
		capacity = 1
	}
	if conf.GlobalOps.MaxParallelism > 0 && capacity > conf.GlobalOps.MaxParallelism {
		capacity = conf.GlobalOps.MaxParallelism
	}
	return capacity * 2
}

func (e *Engine) runSendPacer(ctx context.Context) {
	if e.sendTokens == nil || e.sendRate <= 0 {
		return
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	budget := 0.0
	quantum := e.sendRate / 100.0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			budget += quantum
			tokens := int(budget)
			if tokens == 0 {
				continue
			}
			budget -= float64(tokens)
		fill:
			for i := 0; i < tokens; i++ {
				select {
				case e.sendTokens <- struct{}{}:
				default:
					break fill
				}
			}
		}
	}
}

func (e *Engine) waitSendTurn(ctx context.Context) error {
	if e.sendTokens == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.sendTokens:
		return nil
	}
}

func drainTensorChannel(ch chan PacketTensor) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func decodeICMPMatch(packetData []byte, outerIPHeaderLen int) (uint16, uint32, uint16, bool) {
	transportStart := 14 + outerIPHeaderLen
	if len(packetData) < transportStart+8 {
		return 0, 0, 0, false
	}

	icmpType := packetData[transportStart]
	if icmpType == 0 || icmpType == 8 {
		channelID, ok := decodeChannelPort(binary.BigEndian.Uint16(packetData[transportStart+4 : transportStart+6]))
		if !ok {
			return 0, 0, 0, false
		}
		return channelID, binary.BigEndian.Uint32(packetData[26:30]), 0, true
	}

	innerIPStart := transportStart + 8
	if len(packetData) < innerIPStart+20 {
		return 0, 0, 0, false
	}

	innerIHL := int(packetData[innerIPStart]&0x0F) * 4
	if len(packetData) < innerIPStart+innerIHL {
		return 0, 0, 0, false
	}

	targetIP := binary.BigEndian.Uint32(packetData[innerIPStart+16 : innerIPStart+20])
	innerProtocol := packetData[innerIPStart+9]
	transportOffset := innerIPStart + innerIHL

	switch innerProtocol {
	case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
		if len(packetData) < transportOffset+4 {
			return 0, 0, 0, false
		}
		channelID, ok := decodeChannelPort(binary.BigEndian.Uint16(packetData[transportOffset : transportOffset+2]))
		if !ok {
			return 0, 0, 0, false
		}
		targetPort := binary.BigEndian.Uint16(packetData[transportOffset+2 : transportOffset+4])
		return channelID, targetIP, targetPort, true
	case 1:
		if len(packetData) < transportOffset+6 {
			return 0, 0, 0, false
		}
		channelID, ok := decodeChannelPort(binary.BigEndian.Uint16(packetData[transportOffset+4 : transportOffset+6]))
		if !ok {
			return 0, 0, 0, false
		}
		return channelID, targetIP, 0, true
	default:
		return 0, 0, 0, false
	}
}

func (e *Engine) printReport() {
	fmt.Printf("\n================ L4 Engine Report =================\n")
	if e.sendRate > 0 {
		fmt.Printf("Effective Send Rate: %.0f pps\n", e.sendRate)
	} else {
		fmt.Printf("Effective Send Rate: unlimited\n")
	}
	fmt.Printf("Parallelism Window: %d/%d\n", conf.GlobalOps.MinParallelism, conf.GlobalOps.MaxParallelism)
	fmt.Printf("Current Capacity: %d | Active Probes: %d\n", atomic.LoadInt32(&e.currentCapacity), atomic.LoadInt32(&e.activeProbes))
	fmt.Printf("Smoothed RTO: %d ms | Max RTO: %d ms\n", atomic.LoadInt64(&e.rto), conf.GlobalOps.MaxRTTTimeout)
	fmt.Printf("Packets Sent: %d | Matched Replies: %d | Dispatcher Drops: %d\n",
		MetricPacketsSent.Read(), MetricPacketsMatch.Read(), MetricDispatchDrops.Read())
	fmt.Printf("Tasks Done: %d | Filtered: %d | Open Ports: %d\n",
		MetricTasksDone.Read(), MetricFiltered.Read(), MetricOpenPorts.Read())
	if stats, err := e.pcapHandle.Stats(); err == nil && stats != nil {
		fmt.Printf("Pcap Stats: recv=%d drop=%d ifdrop=%d\n",
			stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
	}
	fmt.Printf("===================================================\n")
}
