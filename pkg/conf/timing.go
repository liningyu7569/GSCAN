package conf

// 假设 GlobalOps 已经包含你提供的 MinParallelism, MaxParallelism, MaxRetries 等字段

func ApplyTimingTemplate() {
	// 如果用户通过命令行明确指定了参数，则跳过覆盖；此处演示基础逻辑
	switch GlobalOps.TimingLevel {
	case 1: // T1 (潜行模式) - 极低并发，高重传，长等待。严格遵守 AIMD。
		setDefault(&GlobalOps.MinParallelism, 1)
		setDefault(&GlobalOps.MaxParallelism, 10)
		setDefault(&GlobalOps.MaxRetries, 3)
		setDefault(&GlobalOps.MaxRTTTimeout, 5000)
		setDefaultFloat(&GlobalOps.MaxPacketSendRate, 50)
		// 初始 RTO 强制拉高
	case 2: // T2 (温和模式) - 低并发，中等重传。
		setDefault(&GlobalOps.MinParallelism, 10)
		setDefault(&GlobalOps.MaxParallelism, 100)
		setDefault(&GlobalOps.MaxRetries, 2)
		setDefault(&GlobalOps.MaxRTTTimeout, 2000)
		setDefaultFloat(&GlobalOps.MaxPacketSendRate, 200)
	case 3: // T3 (普通模式) - 默认均衡状态。
		setDefault(&GlobalOps.MinParallelism, 100)
		setDefault(&GlobalOps.MaxParallelism, 1000)
		setDefault(&GlobalOps.MaxRetries, 1)
		setDefault(&GlobalOps.MaxRTTTimeout, 1000)
		setDefaultFloat(&GlobalOps.MaxPacketSendRate, 1000)
	case 4: // T4 (激进模式) - 高并发，无视静默包，关闭 AIMD 乘性减。
		setDefault(&GlobalOps.MinParallelism, 512)
		setDefault(&GlobalOps.MaxParallelism, 4096)
		setDefault(&GlobalOps.MaxRetries, 1)
		setDefault(&GlobalOps.MaxRTTTimeout, 800)
		setDefaultFloat(&GlobalOps.MaxPacketSendRate, 3000)
	case 5: // T5 (极限模式) - 硬件物理极限，绝对静态并发，零重传，极短超时。
		setDefault(&GlobalOps.MinParallelism, 1024)
		setDefault(&GlobalOps.MaxParallelism, 8192)
		setDefault(&GlobalOps.MaxRetries, 1)
		setDefault(&GlobalOps.MaxRTTTimeout, 600)
		setDefaultFloat(&GlobalOps.MaxPacketSendRate, 6000)
	default:
		GlobalOps.TimingLevel = 3
		ApplyTimingTemplate()
		return
	}

	if GlobalOps.MaxParallelism < GlobalOps.MinParallelism {
		GlobalOps.MaxParallelism = GlobalOps.MinParallelism
	}
	if GlobalOps.MaxRTTTimeout <= 0 {
		GlobalOps.MaxRTTTimeout = 1000
	}
	if GlobalOps.MaxRetries < 0 {
		GlobalOps.MaxRetries = 0
	}
}

func setDefault(target *int, value int) {
	if *target == 0 {
		*target = value
	}
}

func setDefaultFloat(target *float32, value float32) {
	if *target == 0 {
		*target = value
	}
}
