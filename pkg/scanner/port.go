package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ScanTCPPort(target string, port uint16) (string, error) {

	//检查目标地址
	dstIP := net.ParseIP(target)
	if dstIP == nil {
		return "error", fmt.Errorf("invalid IP: %s", target)
	}
	//获取本机地址
	srcIP, err := getLocalIP()
	if err != nil {
		return "error", fmt.Errorf("get local IP: %v", err)
	}
	fmt.Printf("Scanning %s:%d from %s\n", target, port, srcIP)
	//获取网口
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		return "error", fmt.Errorf("get interface by name: %v", err)
	}
	//目标MAC
	dstMAC, err := getGatewayMAC()
	if err != nil {
		return "error", fmt.Errorf("get gateway MAC: %v", err)
	}
	// 打开 pcap 句柄
	handle, err := pcap.OpenLive("en0", 1500, true, pcap.BlockForever)
	if err != nil {
		return "error", fmt.Errorf("open pcap: %v", err)
	}
	defer handle.Close()

	// 设置 BPF 过滤器（捕获目标返回的 TCP 包）
	filter := fmt.Sprintf("tcp and src host %s ", target)
	fmt.Printf("BPF Filter: %s\n", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		return "error", fmt.Errorf("set BPF filter: %v", err)
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	// 构建 TCP SYN 包
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Version:  4,
		IHL:      5,
	}
	//tcp := layers.TCP{
	//	SrcPort: layers.TCPPort(rand.Intn(65535-1024) + 1024),
	//	DstPort: layers.TCPPort(port),
	//	Seq:     rand.Uint32(),
	//	SYN:     true,
	//	Window:  1024,
	//	Options: nil,
	//	//Options: []layers.TCPOption{
	//	//	{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xB4}}, // MSS=1460
	//	//},
	//}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rand.Intn(65535-1024) + 1024),
		DstPort: layers.TCPPort(port),
		Seq:     rand.Uint32(),
		SYN:     true,
		Window:  1024,
		Options: []layers.TCPOption{}, // 显式空选项
	}
	// 设置 TCP 校验和
	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		return "error", fmt.Errorf("set TCP checksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp); err != nil {
		return "error", fmt.Errorf("serialize layers: %v", err)
	}
	packet := buf.Bytes()
	fmt.Printf("Sending TCP SYN: %x\n", packet)
	if len(packet) > 54 { // Ethernet 14 + IP 20 + TCP 20
		packet = packet[:54] // 修剪多余填充
		fmt.Printf("Trimmed packet to: %x\n", packet)
	}
	// 发送包
	if err := handle.WritePacketData(packet); err != nil {
		fmt.Println("Send error:", err)
		return "error", err
	}

	// 接收响应
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	timeout := time.After(10 * time.Second)
	for {
		select {
		case packet := <-packetSource.Packets():
			fmt.Printf("Received packet: %x\n", packet.Data())
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcpResp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("TCP Flags: SYN=%v, ACK=%v, RST=%v, SrcPort=%v, DstPort=%v\n",
					tcpResp.SYN, tcpResp.ACK, tcpResp.RST, tcpResp.SrcPort, tcpResp.DstPort)
				if tcpResp.SYN && tcpResp.ACK {
					return "open", nil
				} else if tcpResp.RST {
					return "closed", nil
				}
			}
		case <-timeout:
			fmt.Println("Timeout waiting for response")
			return "filtered", nil
		}
	}
}

// getGatewayMAC 获取默认网关的 MAC 地址（通过 arp 命令）
func getGatewayMAC() (net.HardwareAddr, error) {
	// 获取默认网关 IP
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("get default route: %v", err)
	}
	re := regexp.MustCompile(`gateway: (\S+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return nil, fmt.Errorf("no gateway found")
	}
	gatewayIP := matches[1]

	// 通过 arp -a 获取网关的 MAC 地址
	cmd = exec.Command("arp", "-a")
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("arp lookup: %v", err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, gatewayIP) {
			reMAC := regexp.MustCompile(`([0-9a-fA-F:]{17})`)
			macStr := reMAC.FindString(line)
			if macStr != "" {
				return net.ParseMAC(macStr)
			}
		}
	}
	return nil, fmt.Errorf("no MAC found for gateway %s", gatewayIP)
}
