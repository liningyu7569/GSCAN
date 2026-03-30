package queue

import (
	"runtime"
	"sync/atomic"
)

// ScanResult 仅保留最核心的数据，确保结构体紧凑
type ScanResult struct {
	IP       uint32
	Port     uint16
	Protocol uint8
}

type slot struct {
	sequence uint64
	data     ScanResult
}

type LockFreeRingBuffer struct {
	capacity uint64
	mask     uint64
	_pad0    [56]byte // 隔离底层元数据，防止与 head 发生伪共享
	head     uint64
	_pad1    [56]byte // 隔离 head 与 tail
	tail     uint64
	_pad2    [56]byte
	buffer   []slot
}

// NewLockFreeRingBuffer 初始化，capacity 必须是 2 的幂
func NewLockFreeRingBuffer(capacity uint64) *LockFreeRingBuffer {
	if capacity&(capacity-1) != 0 {
		panic("capacity 必须是 2 的幂")
	}
	rb := &LockFreeRingBuffer{
		capacity: capacity,
		mask:     capacity - 1,
		buffer:   make([]slot, capacity),
	}
	for i := uint64(0); i < capacity; i++ {
		rb.buffer[i].sequence = i
	}
	return rb
}

// Push 扫描探针（生产者）调用。使用 CAS 获取写入槽位，无阻塞。
func (rb *LockFreeRingBuffer) Push(data ScanResult) bool {
	var cell *slot
	var pos uint64
	for {
		pos = atomic.LoadUint64(&rb.head)
		cell = &rb.buffer[pos&rb.mask]
		seq := atomic.LoadUint64(&cell.sequence)
		dif := int64(seq) - int64(pos)

		if dif == 0 {
			// 槽位可用，尝试 CAS 推进 head
			if atomic.CompareAndSwapUint64(&rb.head, pos, pos+1) {
				break
			}
		} else if dif < 0 {
			// 缓冲区满
			return false
		} else {
			// 并发竞争，让出时间片
			runtime.Gosched()
		}
	}
	// 写入数据并更新 sequence，标记为可读
	cell.data = data
	atomic.StoreUint64(&cell.sequence, pos+1)
	return true
}

// Pop 消费者协程调用（批处理模块）。
func (rb *LockFreeRingBuffer) Pop(data *ScanResult) bool {
	var cell *slot
	var pos uint64
	for {
		pos = atomic.LoadUint64(&rb.tail)
		cell = &rb.buffer[pos&rb.mask]
		seq := atomic.LoadUint64(&cell.sequence)
		dif := int64(seq) - int64(pos+1)

		if dif == 0 {
			// 数据就绪，尝试 CAS 推进 tail
			if atomic.CompareAndSwapUint64(&rb.tail, pos, pos+1) {
				break
			}
		} else if dif < 0 {
			// 缓冲区空
			return false
		} else {
			runtime.Gosched()
		}
	}
	// 提取数据并重置 sequence，标记为可写
	*data = cell.data
	atomic.StoreUint64(&cell.sequence, pos+rb.mask+1)
	return true
}
