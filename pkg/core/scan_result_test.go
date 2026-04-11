package core

import (
	"Going_Scan/pkg/queue"
	"encoding/binary"
	"syscall"
	"testing"
)

func TestEvaluateTaskResultForAckAndWindow(t *testing.T) {
	tcpHeader := makeIPv4Header(64, syscall.IPPROTO_TCP)

	rstZeroWindow := make([]byte, 20)
	rstZeroWindow[13] = FlagRST | FlagACK
	binary.BigEndian.PutUint16(rstZeroWindow[14:16], 0)
	rstZeroTensor := ExtractTensor(tcpHeader, rstZeroWindow)

	ackTask := EmissionTask{Protocol: syscall.IPPROTO_TCP, ScanKind: ScanKindTCPACK}
	if got := evaluateTaskResult(ackTask, rstZeroTensor); got != ScanStateUnfiltered {
		t.Fatalf("unexpected ACK result state: got %d want %d", got, ScanStateUnfiltered)
	}

	windowTask := EmissionTask{Protocol: syscall.IPPROTO_TCP, ScanKind: ScanKindTCPWINDOW}
	if got := evaluateTaskResult(windowTask, rstZeroTensor); got != ScanStateClosed {
		t.Fatalf("unexpected Window closed state: got %d want %d", got, ScanStateClosed)
	}

	rstNonZeroWindow := make([]byte, 20)
	rstNonZeroWindow[13] = FlagRST | FlagACK
	binary.BigEndian.PutUint16(rstNonZeroWindow[14:16], 4096)
	rstNonZeroTensor := ExtractTensor(tcpHeader, rstNonZeroWindow)
	if got := evaluateTaskResult(windowTask, rstNonZeroTensor); got != ScanStateOpen {
		t.Fatalf("unexpected Window open state: got %d want %d", got, ScanStateOpen)
	}
}

func TestEvaluateTaskResultForICMPFilteredAndUDPClosed(t *testing.T) {
	filteredTensor := ExtractTensor(makeIPv4Header(48, syscall.IPPROTO_ICMP), []byte{3, 13, 0, 0})
	if got := evaluateTaskResult(EmissionTask{Protocol: syscall.IPPROTO_TCP, ScanKind: ScanKindTCPACK}, filteredTensor); got != ScanStateFiltered {
		t.Fatalf("unexpected ACK filtered state: got %d want %d", got, ScanStateFiltered)
	}

	udpClosedTensor := ExtractTensor(makeIPv4Header(48, syscall.IPPROTO_ICMP), []byte{3, 3, 0, 0})
	if got := evaluateTaskResult(EmissionTask{Protocol: syscall.IPPROTO_UDP, ScanKind: ScanKindUDP}, udpClosedTensor); got != ScanStateClosed {
		t.Fatalf("unexpected UDP closed state: got %d want %d", got, ScanStateClosed)
	}
}

func TestShouldDispatchToL7(t *testing.T) {
	if !shouldDispatchToL7(ScanKindTCPSYN, ScanStateOpen, syscall.IPPROTO_TCP) {
		t.Fatal("expected TCP SYN open result to be eligible for L7")
	}
	if !shouldDispatchToL7(ScanKindUDP, ScanStateOpen, syscall.IPPROTO_UDP) {
		t.Fatal("expected UDP open result to be eligible for L7")
	}
	if shouldDispatchToL7(ScanKindTCPACK, ScanStateUnfiltered, syscall.IPPROTO_TCP) {
		t.Fatal("did not expect ACK result to be eligible for L7")
	}
	if shouldDispatchToL7(ScanKindTCPWINDOW, ScanStateOpen, syscall.IPPROTO_TCP) {
		t.Fatal("did not expect Window open heuristic to be eligible for L7")
	}
}

func TestTranslateQueueResult(t *testing.T) {
	got := translateQueueResult(queue.ScanResult{
		IP:       0xC0A80101,
		Port:     80,
		Protocol: syscall.IPPROTO_TCP,
		ScanKind: ScanKindTCPACK,
		State:    ScanStateUnfiltered,
	})

	if got.Method != "tcp-ack" {
		t.Fatalf("unexpected method: got %q", got.Method)
	}
	if got.State != "unfiltered" {
		t.Fatalf("unexpected state: got %q", got.State)
	}
	if got.IPStr != "192.168.1.1" {
		t.Fatalf("unexpected IP string: got %q", got.IPStr)
	}
}
