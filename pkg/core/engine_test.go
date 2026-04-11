package core

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func TestDecodeICMPMatchForEchoReply(t *testing.T) {
	packet := make([]byte, 14+20+8)
	packet[12], packet[13] = 0x08, 0x00
	packet[14] = 0x45
	packet[23] = syscall.IPPROTO_ICMP
	binary.BigEndian.PutUint32(packet[26:30], 0xC0A80101)

	transportStart := 14 + 20
	packet[transportStart] = 0
	binary.BigEndian.PutUint16(packet[transportStart+4:transportStart+6], encodeChannelPort(7))

	channelID, srcIP, srcPort, ok := decodeICMPMatch(packet, 20)
	if !ok {
		t.Fatal("expected echo reply to match")
	}
	if channelID != 7 {
		t.Fatalf("unexpected channelID: got %d want 7", channelID)
	}
	if srcIP != 0xC0A80101 {
		t.Fatalf("unexpected source IP: got %#x", srcIP)
	}
	if srcPort != 0 {
		t.Fatalf("unexpected source port: got %d want 0", srcPort)
	}
}

func TestDecodeICMPMatchForPortUnreachable(t *testing.T) {
	packet := make([]byte, 14+20+8+20+8)
	packet[12], packet[13] = 0x08, 0x00
	packet[14] = 0x45
	packet[23] = syscall.IPPROTO_ICMP

	transportStart := 14 + 20
	packet[transportStart] = 3
	packet[transportStart+1] = 3

	innerIPStart := transportStart + 8
	packet[innerIPStart] = 0x45
	packet[innerIPStart+9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint32(packet[innerIPStart+16:innerIPStart+20], 0xC0A80164)

	innerTransportStart := innerIPStart + 20
	binary.BigEndian.PutUint16(packet[innerTransportStart:innerTransportStart+2], encodeChannelPort(9))
	binary.BigEndian.PutUint16(packet[innerTransportStart+2:innerTransportStart+4], 53)

	channelID, targetIP, targetPort, ok := decodeICMPMatch(packet, 20)
	if !ok {
		t.Fatal("expected ICMP unreachable to match quoted UDP packet")
	}
	if channelID != 9 {
		t.Fatalf("unexpected channelID: got %d want 9", channelID)
	}
	if targetIP != 0xC0A80164 {
		t.Fatalf("unexpected target IP: got %#x", targetIP)
	}
	if targetPort != 53 {
		t.Fatalf("unexpected target port: got %d want 53", targetPort)
	}
}
