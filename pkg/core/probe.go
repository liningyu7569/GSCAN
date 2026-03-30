package core

//
//// decreaseCWND 执行乘性减 (例如减半)
//func (e *Engine) decreaseCWND() {
//	// 从 Tokens 通道抽离一半令牌，阻止新探针发射
//	currentCap := len(e.Tokens)
//	dropCount := currentCap / 2
//	for i := 0; i < dropCount; i++ {
//		select {
//		case <-e.Tokens:
//		default:
//			return
//		}
//	}
//}
//
//// increaseCWND 执行加性增
//func (e *Engine) increaseCWND() {
//	// 向 Tokens 注入令牌，提高并发上限，逼近网络极限
//	select {
//	case e.Tokens <- struct{}{}:
//	default: // 已达物理上限 MaxCWNDLimit
//	}
//}
//
//// updateRTO Jacobson/Karels 算法更新 RTO
//func (e *Engine) updateRTO(rtt int64) {
//	// 简化版原子更新逻辑
//	srtt := atomic.LoadInt64(&e.srtt)
//	if srtt == 0 {
//		atomic.StoreInt64(&e.srtt, rtt)
//		atomic.StoreInt64(&e.rttvar, rtt/2)
//		atomic.StoreInt64(&e.rto, rtt*3)
//		return
//	}
//	// ... 执行标准公式更新 SRTT 和 RTTVAR，利用 atomic.CompareAndSwapInt64
//}
