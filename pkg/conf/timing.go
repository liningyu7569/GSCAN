package conf

import "time"

// TimingParams 定义了扫描的时间和并发参数
type TimingParams struct {
	InitialCwnd      float64       // 初始并发窗口
	MinCwnd          float64       // 最小并发窗口 (死活不能低于这个)
	MaxScanDelay     time.Duration // 最大发包延迟 (死活不能高于这个)
	MaxRTO           time.Duration // 最大超时时间 (超过这个时间还没回包就认为丢了)
	MinRTO           time.Duration // 最小超时时间
	MaxRetries       int           // 最大重传次数
	IgnoreCongestion bool          // 是否完全忽略拥塞控制 (T5)
}

// GetTimingConfig 根据 TimingLevel (0-5) 返回具体的配置
func GetTimingConfig() TimingParams {
	// 默认 T3
	level := GlobalOps.TimingLevel

	switch level {
	case 0: // T0: Paranoid (极度偏执，用于避开 IDS)
		return TimingParams{
			InitialCwnd:      1.0,
			MinCwnd:          1.0,
			MaxScanDelay:     5 * time.Minute, // 极其慢
			MaxRTO:           5 * time.Minute,
			MinRTO:           1 * time.Minute, // 甚至可以串行
			MaxRetries:       10,              // 既然这么慢，就多试几次
			IgnoreCongestion: false,
		}
	case 1: // T1: Sneaky (偷偷摸摸)
		return TimingParams{
			InitialCwnd:      1.0,
			MinCwnd:          1.0,
			MaxScanDelay:     15 * time.Second,
			MaxRTO:           15 * time.Second,
			MinRTO:           1 * time.Second,
			MaxRetries:       10,
			IgnoreCongestion: false,
		}
	case 2: // T2: Polite (礼貌模式，少占带宽)
		return TimingParams{
			InitialCwnd:      1.0,
			MinCwnd:          1.0,
			MaxScanDelay:     400 * time.Millisecond,
			MaxRTO:           1000 * time.Millisecond,
			MinRTO:           100 * time.Millisecond,
			MaxRetries:       10,
			IgnoreCongestion: false,
		}
	case 4: // T4: Aggressive (激进模式 - 推荐用于现代网络)
		// 这是解决你"卡顿"问题的关键档位
		return TimingParams{
			InitialCwnd:      10.0,                    // 起步就发 10 个
			MinCwnd:          10.0,                    // 哪怕丢包，并发也不低于 10
			MaxScanDelay:     10 * time.Millisecond,   // 延迟最多 10ms，几乎无感
			MaxRTO:           1250 * time.Millisecond, // 超时上限 1.25s
			MinRTO:           100 * time.Millisecond,
			MaxRetries:       2, // 失败了别纠结，重试 2 次够了
			IgnoreCongestion: false,
		}
	case 5: // T5: Insane (疯狗模式 - 牺牲准确性换速度)
		return TimingParams{
			InitialCwnd:      50.0,
			MinCwnd:          75.0,
			MaxScanDelay:     5 * time.Millisecond,
			MaxRTO:           300 * time.Millisecond, // 300ms 没回就当死了
			MinRTO:           50 * time.Millisecond,
			MaxRetries:       1,    // 只重试 1 次
			IgnoreCongestion: true, // 无视拥塞，全速发
		}
	default: // T3: Normal (默认平衡)
		return TimingParams{
			InitialCwnd:      10.0,                    // Nmap 默认初始也比较保守，但我们可以设高点
			MinCwnd:          1.0,                     // 允许降到 1
			MaxScanDelay:     1000 * time.Millisecond, // 允许等待 1 秒
			MaxRTO:           1000 * time.Millisecond, // 动态 RTO
			MinRTO:           100 * time.Millisecond,
			MaxRetries:       3,
			IgnoreCongestion: false,
		}
	}
}
