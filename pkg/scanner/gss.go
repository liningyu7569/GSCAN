package scanner

import (
	"golang.org/x/time/rate"
)

type GlobalScanStats struct {
	//令牌桶算法处理限速
	Limiter *rate.Limiter

	//宏观Cwnd，限制整个扫描任务已经发射的包速率
	Cwnd            float64
	Ssthresh        float64
	NumProbesActive int

	//  统计
	ProbesSent int
}

func NewGSS(maxRate float64) *GlobalScanStats {
	gss := &GlobalScanStats{
		Limiter:         nil,
		Cwnd:            50,
		Ssthresh:        100,
		NumProbesActive: 0,
		ProbesSent:      0,
	}
	if maxRate > 0 {
		gss.Limiter = rate.NewLimiter(rate.Limit(maxRate), 10)
	} else {
		gss.Limiter = rate.NewLimiter(rate.Inf, 0)
	}
	return gss
}
