package metrics

import (
	"sync/atomic"
)

const (
	// CacheLinePadSize: 64 字节缓存行 - 8 字节 int64 = 56 字节
	CacheLinePadSize = 56
	// ShardCount: 强制设置为 2 的幂，利用位与运算替代求余优化性能
	ShardCount = 256
)

// paddedMetric 强制内存对齐，隔离缓存行
type paddedMetric struct {
	count int64
	_     [CacheLinePadSize]byte
}

type ShardedMetrics struct {
	shards [ShardCount]paddedMetric
}

// Add 探针协程调用此方法，传入 channelID 或随机数作为分片因子
func (m *ShardedMetrics) Add(id uint64, delta int64) {
	idx := id & (ShardCount - 1)
	atomic.AddInt64(&m.shards[idx].count, delta)
}

// Read 监控协程异步读取，不阻塞写入
func (m *ShardedMetrics) Read() int64 {
	var total int64
	for i := 0; i < ShardCount; i++ {
		total += atomic.LoadInt64(&m.shards[i].count)
	}
	return total
}
