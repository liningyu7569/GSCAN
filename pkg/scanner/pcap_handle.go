package scanner

import (
	"Going_Scan/pkg/target"
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"net/netip"
	"strings"
)

func OpenPcap(device string, myIP net.IP) (*pcap.Handle, error) {

	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap device %s error: %v", device, err)
	}

	return handle, nil
}

func GenerateBPF(myIP netip.Addr, targets []*target.Target) string {
	//ip := ulit.NetipToStdIP(myIP)
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
