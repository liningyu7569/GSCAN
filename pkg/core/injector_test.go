package core

import (
	"encoding/binary"
	"testing"

	"Going_Scan/pkg/conf"
)

func TestBuildIntoBufferEncodesChannelPortAndTTL(t *testing.T) {
	originalTTL := conf.GlobalOps.TTL
	conf.GlobalOps.TTL = 42
	defer func() {
		conf.GlobalOps.TTL = originalTTL
	}()

	buf := make([]byte, 128)
	task := EmissionTask{
		TargetIP:   0xC0A80101,
		TargetPort: 443,
		Protocol:   6,
		ScanFlags:  0x02,
	}
	route := RouteMeta{
		SrcIP: 0xC0A80164,
		SrcMAC: [6]byte{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		},
		DstMAC: [6]byte{
			0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		},
	}

	packetLen, err := BuildIntoBuffer(&buf, task, 0, route)
	if err != nil {
		t.Fatalf("BuildIntoBuffer returned error: %v", err)
	}
	if packetLen != 54 {
		t.Fatalf("unexpected packet length: got %d want 54", packetLen)
	}

	if got := binary.BigEndian.Uint16(buf[34:36]); got != BaseSourcePort {
		t.Fatalf("unexpected encoded source port: got %d want %d", got, BaseSourcePort)
	}

	if got := buf[22]; got != 42 {
		t.Fatalf("unexpected TTL: got %d want 42", got)
	}
}
