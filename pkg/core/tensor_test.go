package core

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func TestExtractTensorTCPStates(t *testing.T) {
	ipv4Header := makeIPv4Header(64, syscall.IPPROTO_TCP)

	openTransport := make([]byte, 20)
	openTransport[13] = FlagSYN | FlagACK
	binary.BigEndian.PutUint16(openTransport[14:16], 8192)

	openTensor := ExtractTensor(ipv4Header, openTransport)
	if !openTensor.IsTCPStateOpen() {
		t.Fatal("expected SYN+ACK tensor to be open")
	}
	if openTensor.DecodeProtocol() != syscall.IPPROTO_TCP {
		t.Fatalf("unexpected protocol: got %d", openTensor.DecodeProtocol())
	}

	closedTransport := make([]byte, 20)
	closedTransport[13] = FlagRST | FlagACK
	closedTensor := ExtractTensor(ipv4Header, closedTransport)
	if !closedTensor.IsTCPStateClosed() {
		t.Fatal("expected RST tensor to be closed")
	}
}

func TestExtractTensorUDPAndICMP(t *testing.T) {
	udpTensor := ExtractTensor(makeIPv4Header(32, syscall.IPPROTO_UDP), make([]byte, 8))
	if !udpTensor.IsUDPStateOpen() {
		t.Fatal("expected UDP tensor to represent an open UDP response")
	}

	icmpTransport := []byte{3, 3, 0, 0}
	icmpTensor := ExtractTensor(makeIPv4Header(48, syscall.IPPROTO_ICMP), icmpTransport)
	typ, code := icmpTensor.DecodeICMP()
	if typ != 3 || code != 3 {
		t.Fatalf("unexpected ICMP type/code: got (%d,%d)", typ, code)
	}
	if !icmpTensor.IsUDPStateClosed() {
		t.Fatal("expected ICMP port unreachable to mark UDP as closed")
	}
}

func makeIPv4Header(ttl uint8, protocol uint8) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	header[8] = ttl
	header[9] = protocol
	return header
}
