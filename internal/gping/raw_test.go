package gping

import (
	"Going_Scan/pkg/routing"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildSingleActionIncludesRawInjectionParams(t *testing.T) {
	action, err := buildSingleAction("raw", "tcp-raw", Options{
		PayloadHex: "41424344",
		Retries:    2,
		TTL:        33,
		TOS:        16,
		IPID:       321,
		DF:         true,
		BadSum:     true,
		SourcePort: 44444,
		TCPFlags:   "syn,ack",
		TCPSeq:     123,
		TCPAck:     456,
		TCPWindow:  4096,
	}, TargetContext{
		IP:       "198.51.100.10",
		Port:     443,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("buildSingleAction returned error: %v", err)
	}
	if action.Params["ttl"] != 33 || action.Params["src_port"] != 44444 {
		t.Fatalf("unexpected raw params: %+v", action.Params)
	}
	if action.Params["tcp_flags"] != "syn,ack" || action.Params["payload_hex"] != "41424344" {
		t.Fatalf("unexpected raw params: %+v", action.Params)
	}
	if action.Params["bad_checksum"] != true || action.Params["retries"] != 2 {
		t.Fatalf("unexpected raw params: %+v", action.Params)
	}
}

func TestApplyActionProtocolInfersRawMethods(t *testing.T) {
	tcpTarget := applyActionProtocol(TargetContext{
		IP:       "127.0.0.1",
		Port:     80,
		Protocol: "icmp",
	}, []ActionUnit{
		{Route: "raw", Method: "tcp-raw"},
	})
	if tcpTarget.Protocol != "tcp" {
		t.Fatalf("unexpected inferred protocol for tcp-raw: got %q want tcp", tcpTarget.Protocol)
	}

	icmpTarget := applyActionProtocol(TargetContext{
		IP:       "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
		URL:      "http://127.0.0.1/",
	}, []ActionUnit{
		{Route: "raw", Method: "icmp-raw"},
	})
	if icmpTarget.Protocol != "icmp" || icmpTarget.URL != "" {
		t.Fatalf("unexpected inferred target for icmp-raw: %+v", icmpTarget)
	}
}

func TestBuildRawTCPPacketAppliesInjectionParams(t *testing.T) {
	route := testRawRouteInfo()
	dstIP := net.ParseIP("198.51.100.20").To4()
	goodPacket, err := buildRawTCPPacket(route, dstIP, 443, rawTCPProbeConfig{
		SrcPort:     44444,
		Seq:         12345,
		Ack:         67890,
		Window:      4096,
		TTL:         37,
		TOS:         16,
		IPID:        321,
		DF:          true,
		Payload:     []byte("ABCD"),
		Flags:       rawTCPFlags{SYN: true, ACK: true, PSH: true},
		Retries:     1,
		BadChecksum: false,
	})
	if err != nil {
		t.Fatalf("buildRawTCPPacket returned error: %v", err)
	}
	badPacket, err := buildRawTCPPacket(route, dstIP, 443, rawTCPProbeConfig{
		SrcPort:     44444,
		Seq:         12345,
		Ack:         67890,
		Window:      4096,
		TTL:         37,
		TOS:         16,
		IPID:        321,
		DF:          true,
		Payload:     []byte("ABCD"),
		Flags:       rawTCPFlags{SYN: true, ACK: true, PSH: true},
		BadChecksum: true,
	})
	if err != nil {
		t.Fatalf("buildRawTCPPacket returned error: %v", err)
	}

	good := gopacket.NewPacket(goodPacket, layers.LayerTypeEthernet, gopacket.Default)
	bad := gopacket.NewPacket(badPacket, layers.LayerTypeEthernet, gopacket.Default)
	ipLayer := good.Layer(layers.LayerTypeIPv4)
	tcpLayer := good.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		t.Fatalf("expected IPv4 and TCP layers in raw packet")
	}
	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)
	if ip.TTL != 37 || ip.TOS != 16 || ip.Id != 321 {
		t.Fatalf("unexpected IPv4 fields: ttl=%d tos=%d id=%d", ip.TTL, ip.TOS, ip.Id)
	}
	if ip.Flags&layers.IPv4DontFragment == 0 {
		t.Fatalf("expected DF flag to be set")
	}
	if uint16(tcp.SrcPort) != 44444 || uint16(tcp.DstPort) != 443 {
		t.Fatalf("unexpected TCP ports: %d -> %d", tcp.SrcPort, tcp.DstPort)
	}
	if tcp.Seq != 12345 || tcp.Ack != 67890 || tcp.Window != 4096 {
		t.Fatalf("unexpected TCP sequence fields: seq=%d ack=%d window=%d", tcp.Seq, tcp.Ack, tcp.Window)
	}
	if !tcp.SYN || !tcp.ACK || !tcp.PSH {
		t.Fatalf("unexpected TCP flags: %+v", tcp)
	}
	if string(tcp.Payload) != "ABCD" {
		t.Fatalf("unexpected TCP payload: %q", string(tcp.Payload))
	}

	badTCPLayer := bad.Layer(layers.LayerTypeTCP)
	if badTCPLayer == nil {
		t.Fatalf("expected TCP layer in bad checksum packet")
	}
	if tcp.Checksum == badTCPLayer.(*layers.TCP).Checksum {
		t.Fatalf("expected corrupted TCP checksum to differ")
	}
}

func TestBuildRawICMPPacketAppliesInjectionParams(t *testing.T) {
	route := testRawRouteInfo()
	dstIP := net.ParseIP("198.51.100.30").To4()
	goodPacket, err := buildRawICMPPacket(route, dstIP, rawICMPProbeConfig{
		Type:        layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Identifier:  123,
		Sequence:    456,
		TTL:         29,
		TOS:         8,
		IPID:        222,
		DF:          true,
		Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
		BadChecksum: false,
	})
	if err != nil {
		t.Fatalf("buildRawICMPPacket returned error: %v", err)
	}
	badPacket, err := buildRawICMPPacket(route, dstIP, rawICMPProbeConfig{
		Type:        layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Identifier:  123,
		Sequence:    456,
		TTL:         29,
		TOS:         8,
		IPID:        222,
		DF:          true,
		Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
		BadChecksum: true,
	})
	if err != nil {
		t.Fatalf("buildRawICMPPacket returned error: %v", err)
	}

	good := gopacket.NewPacket(goodPacket, layers.LayerTypeEthernet, gopacket.Default)
	bad := gopacket.NewPacket(badPacket, layers.LayerTypeEthernet, gopacket.Default)
	ipLayer := good.Layer(layers.LayerTypeIPv4)
	icmpLayer := good.Layer(layers.LayerTypeICMPv4)
	if ipLayer == nil || icmpLayer == nil {
		t.Fatalf("expected IPv4 and ICMPv4 layers in raw packet")
	}
	ip := ipLayer.(*layers.IPv4)
	icmp := icmpLayer.(*layers.ICMPv4)
	if ip.TTL != 29 || ip.TOS != 8 || ip.Id != 222 {
		t.Fatalf("unexpected IPv4 fields: ttl=%d tos=%d id=%d", ip.TTL, ip.TOS, ip.Id)
	}
	if ip.Flags&layers.IPv4DontFragment == 0 {
		t.Fatalf("expected DF flag to be set")
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || icmp.Id != 123 || icmp.Seq != 456 {
		t.Fatalf("unexpected ICMP fields: type=%d id=%d seq=%d", icmp.TypeCode.Type(), icmp.Id, icmp.Seq)
	}

	badICMPLayer := bad.Layer(layers.LayerTypeICMPv4)
	if badICMPLayer == nil {
		t.Fatalf("expected ICMP layer in bad checksum packet")
	}
	if icmp.Checksum == badICMPLayer.(*layers.ICMPv4).Checksum {
		t.Fatalf("expected corrupted ICMP checksum to differ")
	}
}

func TestInterpretTCPRawRSTProducesClosedClaim(t *testing.T) {
	report := interpretEvidence(TargetContext{
		IP:       "198.51.100.40",
		Port:     80,
		Protocol: "tcp",
	}, ActionUnit{
		Route:  "raw",
		Method: "tcp-raw",
	}, routeEvidence{
		RawStatus: "rst-ack",
		Extra: map[string]any{
			"flags": "rst,ack",
		},
	})
	if !hasClaim(report, "network", "port_state", "closed") {
		t.Fatalf("expected network.port_state=closed claim, got %+v", report.Claims)
	}
}

func testRawRouteInfo() *routing.RouteInfo {
	return &routing.RouteInfo{
		SrcIP:        net.IPv4(192, 0, 2, 10),
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
}
