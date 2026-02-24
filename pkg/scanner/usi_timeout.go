package scanner

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/target"
	"fmt"
	"time"
)

func (usi *UltraScanInfo) processTimeouts() {
	now := time.Now()
	cfg := conf.GetTimingConfig()

	for _, hss := range usi.IncompleteHosts {
		//遍历所有活跃主机的发送探针
		for key, probe := range hss.ProbesOutstanding {
			//计算超时
			if now.Sub(probe.SentTime) > hss.Timeout {
				//惩罚单机，削减窗口
				hss.PunishCongestion()
				//记录超时，宏观调控
				usi.recordTimeout()
				//丢包计数，判断当前活跃状态
				usi.GStats.NumProbesActive--

				fmt.Println("key", key, "port", probe.Port, "重传次数", probe.Retries)
				//重传次数判断，是否放弃
				if probe.Retries >= cfg.MaxRetries {
					//直接更新端口
					lookup := GlobalPorts.Maps[probe.Proto].Lookup
					hss.Target.SetStateByPort(probe.Proto, uint(probe.Port), uint8(target.PortFiltered), lookup)

					//若重传次数>3，则删除该探针
					delete(hss.ProbesOutstanding, key)

					continue
				} else {
					//处理重传，修正当前时间防止再次被超时扫描
					probe.SentTime = now.Add(1 * time.Hour)
					//将包置于发包队列，且优先发包
					hss.RetryQueue = append(hss.RetryQueue, probe)
				}

			}

		}

	}
}
