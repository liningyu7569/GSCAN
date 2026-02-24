package scanner

import (
	"Going_Scan/pkg/conf"
	"time"
)

const (
	DefaultTimeout     = 1000 * time.Millisecond
	MinTimeout         = 100 * time.Millisecond
	MaxTimeout         = 10 * time.Second // 10s
	InitialCwnd        = 10.0
	SlowStartThreshold = 75.0 // 75.0，允许慢启动
	MinCwnd            = 1.0  // 统一使用 float
)

// UpdateCongestion 收到有效回包时调用 (奖励)
func (hss *HostScanStats) UpdateCongestion(rtt time.Duration) {
	cfg := conf.GetTimingConfig()

	// 1. Jacobson/Karels 算法更新 RTT
	if hss.Srtt == 0 {
		hss.Srtt = rtt
		hss.RttVar = rtt / 2
	} else {
		delta := rtt - hss.Srtt
		if delta < 0 {
			delta = -delta
		}
		// RttVar 权重 1/4
		hss.RttVar = (hss.RttVar*3 + delta) / 4
		// Srtt 权重 1/8
		hss.Srtt = (hss.Srtt*7 + rtt) / 8
	}

	// 2. 重新计算 RTO
	hss.Timeout = hss.Srtt + hss.RttVar*4

	// 3. RTO 边界钳制
	if hss.Timeout < cfg.MinRTO {
		hss.Timeout = cfg.MinRTO
	} else if hss.Timeout > cfg.MinRTO {
		hss.Timeout = cfg.MinRTO
	}

	// 4. 调整拥塞窗口 (核心流控)
	if hss.Cwnd < hss.Ssthresh {
		// --- 慢启动阶段 (Slow Start) ---
		// 指数增长: 每收到一个包，窗口+1
		hss.Cwnd += 1.0
	} else {
		// --- 拥塞避免阶段 (Congestion Avoidance) ---
		// 线性增长: 每收到一个包，窗口增加 1/Cwnd
		hss.Cwnd += 1.0 / hss.Cwnd
	}

	// 5. 减少发包延迟 (试探性加速)
	if hss.HostScanDelay > 0 {
		hss.HostScanDelay = time.Duration(float64(hss.HostScanDelay) * 0.8)
		// 如果延迟小于 5ms，直接归零，全速运行
		if hss.HostScanDelay < 5*time.Millisecond {
			hss.HostScanDelay = 0
		}
	}
}

// PunishCongestion 发生超时或丢包时调用 (惩罚)
func (hss *HostScanStats) PunishCongestion() {
	cfg := conf.GetTimingConfig()

	if cfg.IgnoreCongestion {
		return
	}
	// 0. 调整阈值: 当前窗口的一半
	hss.Ssthresh = hss.Cwnd / 2
	if hss.Ssthresh < 2.0 {
		hss.Ssthresh = 2.0 // 保持最小阈值
	}
	// 1. 窗口减半，但受 MinCwnd 托底
	newCwnd := hss.Cwnd / 2.0
	if newCwnd < cfg.MinCwnd {
		newCwnd = cfg.MinCwnd // 【核心解决卡顿点】
	}
	hss.Cwnd = newCwnd

	// 2. 增加延迟，但受 MaxScanDelay 封顶
	if hss.HostScanDelay == 0 {
		hss.HostScanDelay = 5 * time.Millisecond
	} else {
		hss.HostScanDelay *= 2
	}
	if hss.HostScanDelay > cfg.MaxScanDelay {
		hss.HostScanDelay = cfg.MaxScanDelay // 【核心解决卡顿点】
	}

	// 3. RTO 退避
	hss.Timeout *= 2
	if hss.Timeout > cfg.MaxRTO {
		hss.Timeout = cfg.MaxRTO
	}
}
