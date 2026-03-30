package core

import (
	"Going_Scan/pkg/target"
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"net/netip"
	"strings"
	"time"
)

func OpenPcap(device string, myIP net.IP) (*pcap.Handle, error) {

	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap device %s error: %v", device, err)
	}

	return handle, nil
}

func GenerateBPF(myIP netip.Addr, targets []*target.Target) string {
	//ip := util.NetipToStdIP(myIP)
	baseFilter := fmt.Sprintf("dst host %s and (tcp or udp)", myIP.String())

	if len(targets) > 20 {
		return baseFilter
	}

	var sb strings.Builder
	sb.WriteString(baseFilter)
	sb.WriteString("and (")
	for i, t := range targets {
		if i > 0 {
			sb.WriteString(" or ")
		}
		sb.WriteString("src host")
		sb.WriteString(t.TargetIpAddr().String())
	}
	sb.WriteString(")")
	return sb.String()
}

// InitPcap 打开网卡，并应用严格的 BPF 过滤规则
func InitPcap(deviceName string, localIP string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err != nil {
		return nil, fmt.Errorf("打开网卡 %s 失败: %v", deviceName, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(65536); err != nil {
		return nil, fmt.Errorf("设置抓包长度失败: %v", err)
	}
	if err := inactive.SetPromisc(false); err != nil {
		return nil, fmt.Errorf("设置混杂模式失败: %v", err)
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		fmt.Printf("[Pcap] warning: 无法开启即时模式: %v\n", err)
	}
	if err := inactive.SetBufferSize(4 * 1024 * 1024); err != nil {
		fmt.Printf("[Pcap] warning: 无法放大抓包缓冲: %v\n", err)
	}
	if err := inactive.SetTimeout(100 * time.Millisecond); err != nil {
		return nil, fmt.Errorf("设置抓包超时失败: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("激活网卡 %s 失败: %v", deviceName, err)
	}

	// 【架构核心】：极其严格的 BPF 过滤器
	// 1. 目标 IP 必须是我们的扫描机 IP (只抓回包，不抓我们发出去的包)
	// 2. 协议限定为 tcp 或 udp 或 icmp
	bpfFilter := fmt.Sprintf("dst host %s and (tcp or udp or icmp)", localIP)

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("设置 BPF 过滤器失败: %v", err)
	}

	fmt.Printf("[Pcap] 网卡 %s 监听就绪, BPF: %s\n", deviceName, bpfFilter)
	return handle, nil
}
