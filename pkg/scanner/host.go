package scanner

import (
	"fmt"
	"net"
)

// PingHost 发送 ICMP Echo 用于测试主机活跃
// Args: target:目标IP,
// return: bool:是否活跃,error
func PingHost(target string) (bool, error) {
	//检查目标IP格式
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		return false, fmt.Errorf("invaild IP :%s", target)
	}
	//srcIP := net.ParseIP(target)

	//engine, err := NewRawSocketEngine(syscall.IPPROTO_ICMP)
	return false, nil
}
