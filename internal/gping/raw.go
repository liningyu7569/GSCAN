package gping

import (
	"Going_Scan/pkg/routing"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// rawTCPFlags 表示 TCP 头部各标志位
type rawTCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
}

// rawTCPProbeConfig 原始 TCP 探测配置参数
type rawTCPProbeConfig struct {
	SrcPort       uint16
	Seq           uint32
	Ack           uint32
	Window        uint16
	TTL           uint8
	TOS           uint8
	IPID          uint16
	DF            bool
	BadChecksum   bool
	Payload       []byte
	Retries       int
	Flags         rawTCPFlags
	StrictSYNMode bool
}

// rawICMPProbeConfig 原始 ICMP 探测配置参数
type rawICMPProbeConfig struct {
	Type        layers.ICMPv4TypeCode
	Identifier  uint16
	Sequence    uint16
	TTL         uint8
	TOS         uint8
	IPID        uint16
	DF          bool
	BadChecksum bool
	Payload     []byte
	Retries     int
	StrictEcho  bool
}

// executeRaw 执行原始数据包探测（TCP SYN/RAW 或 ICMP），使用 gopacket 收发包
func executeRaw(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	switch normalizeMethod(action.Method) {
	case "tcp-syn", "tcp-raw":
		return executeRawTCP(ctx, target, action)
	case "icmp-echo-raw", "icmp-raw":
		return executeRawICMP(ctx, target, action)
	default:
		return routeEvidence{}, fmt.Errorf("unsupported raw method %q", action.Method)
	}
}

// executeRawTCP 发送自定义 TCP 包并捕获响应，解析标志位状态
func executeRawTCP(_ context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	cfg, err := buildRawTCPProbeConfig(action)
	if err != nil {
		return routeEvidence{}, err
	}

	handle, packetSource, routeInfo, dstIP, cleanup, err := openRawHandle(target, "src host %s and dst host %s and (tcp or icmp)")
	if err != nil {
		return routeEvidence{}, err
	}
	defer cleanup()

	packet, err := buildRawTCPPacket(routeInfo, dstIP, uint16(target.Port), cfg)
	if err != nil {
		return routeEvidence{}, err
	}

	requestSummary := rawTCPRequestSummary(target, cfg)
	timeout := rawTimeout(action.Timeout, 3*time.Second)
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		start := time.Now()
		if err := handle.WritePacketData(packet); err != nil {
			return routeEvidence{}, err
		}

		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			incoming, err := packetSource.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil {
				return routeEvidence{}, err
			}

			if tcpLayer := incoming.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				if uint16(tcp.DstPort) != cfg.SrcPort || int(tcp.SrcPort) != target.Port {
					continue
				}

				flagsText := rawTCPFlagsFromLayer(tcp).DashString()
				status := flagsText
				if status == "" {
					status = "response"
				}
				if cfg.StrictSYNMode {
					switch {
					case tcp.SYN && tcp.ACK:
						status = "open"
					case tcp.RST:
						status = "closed"
					default:
						status = flagsText
					}
				}

				return routeEvidence{
					RawStatus:       status,
					RequestSummary:  requestSummary,
					ResponseSummary: summaryPart("flags", rawTCPFlagsFromLayer(tcp).CSVString()),
					RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
					Extra: map[string]any{
						"flags": rawTCPFlagsFromLayer(tcp).CSVString(),
					},
				}, nil
			}

			if icmpLayer := incoming.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp := icmpLayer.(*layers.ICMPv4)
				status := "icmp-unreachable"
				if cfg.StrictSYNMode && icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
					status = "filtered"
				}
				return routeEvidence{
					RawStatus:       status,
					RequestSummary:  requestSummary,
					ResponseSummary: fmt.Sprintf("icmp=%d/%d", icmp.TypeCode.Type(), icmp.TypeCode.Code()),
					RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
					Extra: map[string]any{
						"icmp_type": icmp.TypeCode.Type(),
						"icmp_code": icmp.TypeCode.Code(),
					},
				}, nil
			}
		}
	}

	status := "timeout"
	if cfg.StrictSYNMode {
		status = "filtered"
	}
	return routeEvidence{
		RawStatus:      status,
		RequestSummary: requestSummary,
		ErrorText:      "timeout waiting for raw response",
	}, nil
}

// executeRawICMP 发送自定义 ICMP 包（如 Echo Request），根据响应判定可达性
func executeRawICMP(_ context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	cfg, err := buildRawICMPProbeConfig(action)
	if err != nil {
		return routeEvidence{}, err
	}

	handle, packetSource, routeInfo, dstIP, cleanup, err := openRawHandle(target, "src host %s and dst host %s and icmp")
	if err != nil {
		return routeEvidence{}, err
	}
	defer cleanup()

	packet, err := buildRawICMPPacket(routeInfo, dstIP, cfg)
	if err != nil {
		return routeEvidence{}, err
	}

	requestSummary := rawICMPRequestSummary(target, cfg)
	timeout := rawTimeout(action.Timeout, 2*time.Second)
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		start := time.Now()
		if err := handle.WritePacketData(packet); err != nil {
			return routeEvidence{}, err
		}

		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			incoming, err := packetSource.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil {
				return routeEvidence{}, err
			}
			icmpLayer := incoming.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv4)
			if cfg.StrictEcho && icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				if icmp.Id != cfg.Identifier || icmp.Seq != cfg.Sequence {
					continue
				}
			}

			status := rawICMPStatus(icmp)
			if cfg.StrictEcho {
				switch icmp.TypeCode.Type() {
				case layers.ICMPv4TypeEchoReply:
					status = "reachable"
				case layers.ICMPv4TypeDestinationUnreachable:
					status = "timeout"
				}
			}

			return routeEvidence{
				RawStatus:       status,
				RequestSummary:  requestSummary,
				ResponseSummary: rawICMPResponseSummary(icmp),
				RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
				Extra: map[string]any{
					"icmp_type": icmp.TypeCode.Type(),
					"icmp_code": icmp.TypeCode.Code(),
				},
			}, nil
		}
	}

	return routeEvidence{
		RawStatus:      "timeout",
		RequestSummary: requestSummary,
		ErrorText:      "timeout waiting for raw response",
	}, nil
}

func openRawHandle(target TargetContext, filterFormat string) (*pcap.Handle, *gopacket.PacketSource, *routing.RouteInfo, net.IP, func(), error) {
	if routing.GlobalRouter == nil {
		if err := routing.InitRouter(); err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}

	dstIP := net.ParseIP(target.IP)
	if dstIP == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid target ip %q", target.IP)
	}

	routeInfo, err := routing.GlobalRouter.RouteTo(dstIP)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	handle, err := pcap.OpenLive(routeInfo.DeviceName, 65536, false, 250*time.Millisecond)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	filter := fmt.Sprintf(filterFormat, dstIP.String(), routeInfo.SrcIP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, nil, nil, nil, nil, err
	}
	return handle, gopacket.NewPacketSource(handle, handle.LinkType()), routeInfo, dstIP, func() {
		handle.Close()
	}, nil
}

func rawTimeout(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func buildRawTCPProbeConfig(action ActionUnit) (rawTCPProbeConfig, error) {
	cfg := rawTCPProbeConfig{
		SrcPort: uint16(40000 + rand.IntN(20000)),
		Seq:     rand.Uint32(),
		Window:  1024,
		TTL:     64,
	}
	payload, err := rawPayloadBytes(action)
	if err != nil {
		return rawTCPProbeConfig{}, err
	}
	cfg.Payload = payload
	cfg.Retries = rawRetryCount(action.Params)

	if value, ok, err := rawParamUint16(action.Params, "src_port", 1, 65535); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.SrcPort = value
	}
	if value, ok, err := rawParamUint32(action.Params, "tcp_seq"); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.Seq = value
	}
	if value, ok, err := rawParamUint32(action.Params, "tcp_ack"); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.Ack = value
	}
	if value, ok, err := rawParamUint16(action.Params, "tcp_window", 0, 65535); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.Window = value
	}
	if value, ok, err := rawParamUint8(action.Params, "ttl", 0, 255); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.TTL = value
	}
	if value, ok, err := rawParamUint8(action.Params, "tos", 0, 255); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.TOS = value
	}
	if value, ok, err := rawParamUint16(action.Params, "ip_id", 0, 65535); err != nil {
		return rawTCPProbeConfig{}, err
	} else if ok {
		cfg.IPID = value
	}
	if rawParamBool(action.Params, "df") {
		cfg.DF = true
	}
	if rawParamBool(action.Params, "bad_checksum") {
		cfg.BadChecksum = true
	}

	flagsText, hasFlags := rawParamString(action.Params, "tcp_flags")
	switch normalizeMethod(action.Method) {
	case "tcp-syn":
		if !hasFlags || strings.TrimSpace(flagsText) == "" {
			cfg.Flags.SYN = true
			cfg.StrictSYNMode = true
			return cfg, nil
		}
	case "tcp-raw":
		if !hasFlags || strings.TrimSpace(flagsText) == "" {
			cfg.Flags.SYN = true
			return cfg, nil
		}
	}
	flags, err := parseRawTCPFlags(flagsText)
	if err != nil {
		return rawTCPProbeConfig{}, err
	}
	cfg.Flags = flags
	cfg.StrictSYNMode = normalizeMethod(action.Method) == "tcp-syn" && flags.IsSYNOnly()
	return cfg, nil
}

func buildRawICMPProbeConfig(action ActionUnit) (rawICMPProbeConfig, error) {
	cfg := rawICMPProbeConfig{
		Type:       layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Identifier: uint16(rand.IntN(65535)),
		Sequence:   uint16(rand.IntN(65535)),
		TTL:        64,
		StrictEcho: normalizeMethod(action.Method) == "icmp-echo-raw",
	}
	payload, err := rawPayloadBytes(action)
	if err != nil {
		return rawICMPProbeConfig{}, err
	}
	cfg.Payload = payload
	cfg.Retries = rawRetryCount(action.Params)

	if value, ok, err := rawParamUint8(action.Params, "ttl", 0, 255); err != nil {
		return rawICMPProbeConfig{}, err
	} else if ok {
		cfg.TTL = value
	}
	if value, ok, err := rawParamUint8(action.Params, "tos", 0, 255); err != nil {
		return rawICMPProbeConfig{}, err
	} else if ok {
		cfg.TOS = value
	}
	if value, ok, err := rawParamUint16(action.Params, "ip_id", 0, 65535); err != nil {
		return rawICMPProbeConfig{}, err
	} else if ok {
		cfg.IPID = value
	}
	if rawParamBool(action.Params, "df") {
		cfg.DF = true
	}
	if rawParamBool(action.Params, "bad_checksum") {
		cfg.BadChecksum = true
	}
	if value, ok, err := rawParamUint16(action.Params, "icmp_id", 0, 65535); err != nil {
		return rawICMPProbeConfig{}, err
	} else if ok {
		cfg.Identifier = value
	}
	if value, ok, err := rawParamUint16(action.Params, "icmp_seq", 0, 65535); err != nil {
		return rawICMPProbeConfig{}, err
	} else if ok {
		cfg.Sequence = value
	}

	typeValue, typeOK, err := rawParamUint8(action.Params, "icmp_type", 0, 255)
	if err != nil {
		return rawICMPProbeConfig{}, err
	}
	codeValue, codeOK, err := rawParamUint8(action.Params, "icmp_code", 0, 255)
	if err != nil {
		return rawICMPProbeConfig{}, err
	}
	if typeOK || codeOK {
		if !typeOK {
			typeValue = uint8(cfg.Type.Type())
		}
		if !codeOK {
			codeValue = uint8(cfg.Type.Code())
		}
		cfg.Type = layers.CreateICMPv4TypeCode(typeValue, codeValue)
	}
	if normalizeMethod(action.Method) == "icmp-raw" {
		cfg.StrictEcho = false
	} else {
		cfg.StrictEcho = cfg.Type.Type() == layers.ICMPv4TypeEchoRequest && cfg.Type.Code() == 0
	}

	return cfg, nil
}

func buildRawTCPPacket(route *routing.RouteInfo, dstIP net.IP, dstPort uint16, cfg rawTCPProbeConfig) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       route.SrcMAC,
		DstMAC:       route.HardwareAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    route.SrcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      cfg.TTL,
		TOS:      cfg.TOS,
		Id:       cfg.IPID,
		Protocol: layers.IPProtocolTCP,
	}
	if cfg.DF {
		ip.Flags = layers.IPv4DontFragment
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(cfg.SrcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     cfg.Seq,
		Ack:     cfg.Ack,
		Window:  cfg.Window,
		FIN:     cfg.Flags.FIN,
		SYN:     cfg.Flags.SYN,
		RST:     cfg.Flags.RST,
		PSH:     cfg.Flags.PSH,
		ACK:     cfg.Flags.ACK,
		URG:     cfg.Flags.URG,
		ECE:     cfg.Flags.ECE,
		CWR:     cfg.Flags.CWR,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	layersToSerialize := []gopacket.SerializableLayer{eth, ip, tcp}
	if len(cfg.Payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(cfg.Payload))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return nil, err
	}
	packet := append([]byte(nil), buf.Bytes()...)
	if cfg.BadChecksum {
		corruptTransportChecksum(packet, 16)
	}
	return packet, nil
}

func buildRawICMPPacket(route *routing.RouteInfo, dstIP net.IP, cfg rawICMPProbeConfig) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       route.SrcMAC,
		DstMAC:       route.HardwareAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    route.SrcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      cfg.TTL,
		TOS:      cfg.TOS,
		Id:       cfg.IPID,
		Protocol: layers.IPProtocolICMPv4,
	}
	if cfg.DF {
		ip.Flags = layers.IPv4DontFragment
	}
	icmp := &layers.ICMPv4{
		TypeCode: cfg.Type,
		Id:       cfg.Identifier,
		Seq:      cfg.Sequence,
	}
	layersToSerialize := []gopacket.SerializableLayer{eth, ip, icmp}
	if len(cfg.Payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(cfg.Payload))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return nil, err
	}
	packet := append([]byte(nil), buf.Bytes()...)
	if cfg.BadChecksum {
		corruptTransportChecksum(packet, 2)
	}
	return packet, nil
}

func corruptTransportChecksum(packet []byte, transportOffset int) {
	if len(packet) < 14+20+transportOffset+2 {
		return
	}
	ipHeaderLength := int(packet[14]&0x0f) * 4
	checksumIndex := 14 + ipHeaderLength + transportOffset
	if checksumIndex+1 >= len(packet) {
		return
	}
	packet[checksumIndex] ^= 0xff
	packet[checksumIndex+1] ^= 0xff
}

func rawRetryCount(params map[string]any) int {
	if value, ok, err := rawParamInt(params, "retries"); err == nil && ok && value > 0 {
		return value
	}
	return 0
}

func rawPayloadBytes(action ActionUnit) ([]byte, error) {
	if value, ok := action.Params["payload_hex"]; ok && strings.TrimSpace(stringAny(value)) != "" {
		return decodeHexBytes(stringAny(value))
	}
	if action.Payload == "" {
		return nil, nil
	}
	return []byte(action.Payload), nil
}

func decodeHexBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "0x")
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\t", "")
	if value == "" {
		return nil, nil
	}
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("payload_hex must contain an even number of hex characters")
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("payload_hex is invalid: %w", err)
	}
	return data, nil
}

func rawTCPRequestSummary(target TargetContext, cfg rawTCPProbeConfig) string {
	parts := []string{
		fmt.Sprintf("tcp %s:%d", target.IP, target.Port),
		summaryPart("src_port", strconv.Itoa(int(cfg.SrcPort))),
		summaryPart("flags", cfg.Flags.CSVString()),
		summaryPart("ttl", strconv.Itoa(int(cfg.TTL))),
		summaryPart("tos", strconv.Itoa(int(cfg.TOS))),
		summaryPart("seq", strconv.FormatUint(uint64(cfg.Seq), 10)),
	}
	if cfg.Ack > 0 {
		parts = append(parts, summaryPart("ack", strconv.FormatUint(uint64(cfg.Ack), 10)))
	}
	if cfg.Window > 0 {
		parts = append(parts, summaryPart("window", strconv.Itoa(int(cfg.Window))))
	}
	if cfg.IPID > 0 {
		parts = append(parts, summaryPart("ip_id", strconv.Itoa(int(cfg.IPID))))
	}
	if cfg.DF {
		parts = append(parts, summaryPart("df", "true"))
	}
	if cfg.BadChecksum {
		parts = append(parts, summaryPart("badsum", "true"))
	}
	if len(cfg.Payload) > 0 {
		parts = append(parts, summaryPart("payload", fmt.Sprintf("%dB", len(cfg.Payload))))
	}
	if cfg.Retries > 0 {
		parts = append(parts, summaryPart("retries", strconv.Itoa(cfg.Retries)))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func rawICMPRequestSummary(target TargetContext, cfg rawICMPProbeConfig) string {
	parts := []string{
		fmt.Sprintf("icmp %s", target.IP),
		summaryPart("type", strconv.Itoa(int(cfg.Type.Type()))),
		summaryPart("code", strconv.Itoa(int(cfg.Type.Code()))),
		summaryPart("id", strconv.Itoa(int(cfg.Identifier))),
		summaryPart("seq", strconv.Itoa(int(cfg.Sequence))),
		summaryPart("ttl", strconv.Itoa(int(cfg.TTL))),
	}
	if cfg.TOS > 0 {
		parts = append(parts, summaryPart("tos", strconv.Itoa(int(cfg.TOS))))
	}
	if cfg.IPID > 0 {
		parts = append(parts, summaryPart("ip_id", strconv.Itoa(int(cfg.IPID))))
	}
	if cfg.DF {
		parts = append(parts, summaryPart("df", "true"))
	}
	if cfg.BadChecksum {
		parts = append(parts, summaryPart("badsum", "true"))
	}
	if len(cfg.Payload) > 0 {
		parts = append(parts, summaryPart("payload", fmt.Sprintf("%dB", len(cfg.Payload))))
	}
	if cfg.Retries > 0 {
		parts = append(parts, summaryPart("retries", strconv.Itoa(cfg.Retries)))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func rawICMPResponseSummary(icmp *layers.ICMPv4) string {
	if icmp == nil {
		return ""
	}
	return fmt.Sprintf("type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
}

func rawICMPStatus(icmp *layers.ICMPv4) string {
	if icmp == nil {
		return "timeout"
	}
	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoReply:
		return "echo-reply"
	case layers.ICMPv4TypeDestinationUnreachable:
		return "destination-unreachable"
	case layers.ICMPv4TypeTimeExceeded:
		return "time-exceeded"
	default:
		return fmt.Sprintf("icmp-%d-%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
}

func rawTCPFlagsFromLayer(tcp *layers.TCP) rawTCPFlags {
	if tcp == nil {
		return rawTCPFlags{}
	}
	return rawTCPFlags{
		FIN: tcp.FIN,
		SYN: tcp.SYN,
		RST: tcp.RST,
		PSH: tcp.PSH,
		ACK: tcp.ACK,
		URG: tcp.URG,
		ECE: tcp.ECE,
		CWR: tcp.CWR,
	}
}

func parseRawTCPFlags(value string) (rawTCPFlags, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return rawTCPFlags{}, nil
	}

	var tokens []string
	if strings.ContainsAny(value, ", |-_/") {
		replacer := strings.NewReplacer(",", " ", "|", " ", "-", " ", "/", " ", "_", " ")
		tokens = strings.Fields(replacer.Replace(value))
	} else if len(value) <= 8 {
		tokens = make([]string, 0, len(value))
		for _, char := range value {
			tokens = append(tokens, string(char))
		}
	} else {
		tokens = []string{value}
	}

	flags := rawTCPFlags{}
	for _, token := range tokens {
		switch strings.TrimSpace(token) {
		case "f", "fin":
			flags.FIN = true
		case "s", "syn":
			flags.SYN = true
		case "r", "rst":
			flags.RST = true
		case "p", "psh":
			flags.PSH = true
		case "a", "ack":
			flags.ACK = true
		case "u", "urg":
			flags.URG = true
		case "e", "ece":
			flags.ECE = true
		case "c", "cwr":
			flags.CWR = true
		default:
			return rawTCPFlags{}, fmt.Errorf("unsupported tcp flag %q", token)
		}
	}
	if !flags.HasAny() {
		return rawTCPFlags{}, fmt.Errorf("tcp_flags did not include any valid flags")
	}
	return flags, nil
}

func (f rawTCPFlags) HasAny() bool {
	return f.FIN || f.SYN || f.RST || f.PSH || f.ACK || f.URG || f.ECE || f.CWR
}

func (f rawTCPFlags) IsSYNOnly() bool {
	return f.SYN && !f.FIN && !f.RST && !f.PSH && !f.ACK && !f.URG && !f.ECE && !f.CWR
}

func (f rawTCPFlags) names() []string {
	names := make([]string, 0, 8)
	if f.FIN {
		names = append(names, "fin")
	}
	if f.SYN {
		names = append(names, "syn")
	}
	if f.RST {
		names = append(names, "rst")
	}
	if f.PSH {
		names = append(names, "psh")
	}
	if f.ACK {
		names = append(names, "ack")
	}
	if f.URG {
		names = append(names, "urg")
	}
	if f.ECE {
		names = append(names, "ece")
	}
	if f.CWR {
		names = append(names, "cwr")
	}
	return names
}

func (f rawTCPFlags) CSVString() string {
	return strings.Join(f.names(), ",")
}

func (f rawTCPFlags) DashString() string {
	return strings.Join(f.names(), "-")
}

func rawParamString(params map[string]any, key string) (string, bool) {
	if len(params) == 0 {
		return "", false
	}
	value, ok := params[key]
	if !ok {
		return "", false
	}
	return strings.TrimSpace(stringAny(value)), true
}

func rawParamBool(params map[string]any, key string) bool {
	if len(params) == 0 {
		return false
	}
	value, ok := params[key]
	if !ok {
		return false
	}
	return boolAny(value)
}

func rawParamInt(params map[string]any, key string) (int, bool, error) {
	text, ok := rawParamString(params, key)
	if !ok || text == "" {
		return 0, false, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, true, fmt.Errorf("%s must be an integer", key)
	}
	return value, true, nil
}

func rawParamUint8(params map[string]any, key string, min int, max int) (uint8, bool, error) {
	value, ok, err := rawParamInt(params, key)
	if err != nil {
		return 0, ok, err
	}
	if !ok {
		return 0, false, nil
	}
	if value < min || value > max {
		return 0, true, fmt.Errorf("%s must be in range %d-%d", key, min, max)
	}
	return uint8(value), true, nil
}

func rawParamUint16(params map[string]any, key string, min int, max int) (uint16, bool, error) {
	value, ok, err := rawParamInt(params, key)
	if err != nil {
		return 0, ok, err
	}
	if !ok {
		return 0, false, nil
	}
	if value < min || value > max {
		return 0, true, fmt.Errorf("%s must be in range %d-%d", key, min, max)
	}
	return uint16(value), true, nil
}

func rawParamUint32(params map[string]any, key string) (uint32, bool, error) {
	text, ok := rawParamString(params, key)
	if !ok || text == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf("%s must be in range 0-4294967295", key)
	}
	return uint32(value), true, nil
}
