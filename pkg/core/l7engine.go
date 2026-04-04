package core

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/l7"
	"Going_Scan/pkg/queue"
	"Going_Scan/pkg/util"
	"context"
	"fmt"
	"sync"
	"time"
)

// L7 核心常量
const (
	MaxL7Workers = 1000 // 严格控制系统 FD (文件描述符) 消耗上限
	L7BufferSize = 4096 // 4KB 足够容纳绝大多数的初始 Banner 和 Header
)

// ScanResult 终极战果结构体 (支持 JSON 序列化落盘)
type ScanResult struct {
	IP       uint32 `json:"-"`        // 内部流转用的高效整型
	IPStr    string `json:"ip"`       // 落盘用的可读字符串
	Port     uint16 `json:"port"`     // 端口
	Protocol uint8  `json:"protocol"` // tcp / udp
	State    string `json:"state"`    // open
	Service  string `json:"service"`  // L7 识别出的服务名 (如 http, ssh)
	Banner   string `json:"banner"`   // 核心指纹特征/响应头
}

// ---------------------------------------------------------
// L7 专属零分配内存池 (Zero-Allocation Buffer Pool)
// ---------------------------------------------------------

var l7BufferPool = sync.Pool{
	New: func() interface{} {
		// 预分配 4KB 的连续内存块
		b := make([]byte, L7BufferSize)
		return &b
	},
}

// GetL7Buffer 借用 Buffer
func GetL7Buffer() *[]byte {
	return l7BufferPool.Get().(*[]byte)
}

// PutL7Buffer 归还 Buffer (无需清空，下次 Read 会直接覆盖有效长度)
func PutL7Buffer(b *[]byte) {
	l7BufferPool.Put(b)
}

// ResultStream 全局唯一的最终战果输出流 (带缓冲防止阻塞 Worker)
var ResultStream = make(chan ScanResult, 10000)

// RunL7Dispatcher L7 指挥官
func (e *Engine) RunL7Dispatcher(ctx context.Context) {
	// ==========================================
	// 降级模式 (快速透传)：未开启 -V 参数
	// ==========================================
	if !conf.GlobalOps.Servicescan {
		fmt.Println("[L7-Engine] 服务识别 (-V) 未开启，执行光速透传模式...")
		var result queue.ScanResult
		for {
			select {
			case <-ctx.Done():
				close(ResultStream)
				return
			default:
				if GlobalResultBuffer.Pop(&result) {
					// 裸数据直接进入持久化层
					ResultStream <- ScanResult{
						IP:       result.IP,
						IPStr:    util.Uint32ToIP(result.IP).String(),
						Port:     result.Port,
						Protocol: result.Protocol,
						State:    "Open",
						Service:  "", // 留空
					}
				} else {
					if e.isL4Finished() {
						close(ResultStream) // 告诉管家 Persister 不要等了，关门落盘！
						fmt.Println("[L7-Engine] 所有 L7 探测任务安全终结。")
						return
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}
	}

	// ==========================================
	// 正常模式 (重装出击)：开启了 -V 参数
	// ==========================================
	l7TaskQueue := make(chan ScanResult, MaxL7Workers*2)
	var wg sync.WaitGroup

	for i := 0; i < MaxL7Workers; i++ {
		wg.Add(1)
		go e.l7ServiceWorker(ctx, &wg, l7TaskQueue)
	}

	fmt.Printf("[L7-Engine] 成功拉起 %d 个服务探活 Worker，等待 L4 战果移交...\n", MaxL7Workers)

	var result queue.ScanResult
	for {
		select {
		case <-ctx.Done():
			close(l7TaskQueue)
			wg.Wait()
			close(ResultStream)
			fmt.Println("[L7-Engine] 所有 L7 探测任务安全终结。")
			return
		default:
			if GlobalResultBuffer.Pop(&result) {
				task := ScanResult{
					IP:       result.IP,
					IPStr:    util.Uint32ToIP(result.IP).String(),
					Port:     result.Port,
					Protocol: result.Protocol,
					State:    "Open",
					Service:  "unknown",
				}
				select {
				case l7TaskQueue <- task:
				case <-ctx.Done():
				}
			} else {
				if e.isL4Finished() {
					close(l7TaskQueue)  // 告诉 L7 Worker 不要再等新活了
					wg.Wait()           // 阻塞等待手头正在 Dial 的 Worker 完成
					close(ResultStream) // 告诉管家 Persister 不要等了，关门落盘！
					fmt.Println("[L7-Engine] 所有 L7 探测任务安全终结。")
					return
				}
				time.Sleep(1 * time.Millisecond)
			}
		}
	}
}

// l7ServiceWorker 完整实现 (加入 protocol 传递)
func (e *Engine) l7ServiceWorker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan ScanResult) {
	defer wg.Done()

	for task := range tasks {
		bufPtr := GetL7Buffer()

		// 【关键修改】传递 Protocol，让底层感知 TCP/UDP
		service, banner := l7.IdentifyService(task.IPStr, task.Port, task.Protocol, bufPtr)

		task.Service = service
		task.Banner = banner

		PutL7Buffer(bufPtr)

		ResultStream <- task
	}
}
