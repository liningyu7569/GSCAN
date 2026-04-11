package core

import "syscall"

const (
	ScanKindUnknown uint8 = iota
	ScanKindTCPSYN
	ScanKindTCPACK
	ScanKindTCPWINDOW
	ScanKindUDP
)

const (
	ScanStateUnknown uint8 = iota
	ScanStateOpen
	ScanStateClosed
	ScanStateFiltered
	ScanStateUnfiltered
)

func scanKindToString(kind uint8) string {
	switch kind {
	case ScanKindTCPSYN:
		return "tcp-syn"
	case ScanKindTCPACK:
		return "tcp-ack"
	case ScanKindTCPWINDOW:
		return "tcp-window"
	case ScanKindUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func scanStateToString(state uint8) string {
	switch state {
	case ScanStateOpen:
		return "open"
	case ScanStateClosed:
		return "closed"
	case ScanStateFiltered:
		return "filtered"
	case ScanStateUnfiltered:
		return "unfiltered"
	default:
		return "unknown"
	}
}

func shouldDispatchToL7(scanKind uint8, state uint8, protocol uint8) bool {
	if state != ScanStateOpen {
		return false
	}

	switch scanKind {
	case ScanKindTCPSYN:
		return protocol == syscall.IPPROTO_TCP
	case ScanKindUDP:
		return protocol == syscall.IPPROTO_UDP
	default:
		return false
	}
}

func shouldEmitResult(scanKind uint8, state uint8) bool {
	switch scanKind {
	case ScanKindTCPSYN, ScanKindUDP:
		return state == ScanStateOpen
	case ScanKindTCPACK, ScanKindTCPWINDOW:
		return state != ScanStateUnknown
	default:
		return false
	}
}

func evaluateTaskResult(task EmissionTask, tensor PacketTensor) uint8 {
	switch task.ScanKind {
	case ScanKindTCPSYN:
		if tensor.IsTCPStateOpen() {
			return ScanStateOpen
		}
		if tensor.IsTCPStateClosed() {
			return ScanStateClosed
		}
		if tensor.IsTCPFiltered() {
			return ScanStateFiltered
		}
	case ScanKindTCPACK:
		if tensor.IsTCPStateClosed() {
			return ScanStateUnfiltered
		}
		if tensor.IsTCPFiltered() {
			return ScanStateFiltered
		}
	case ScanKindTCPWINDOW:
		if tensor.IsTCPStateClosed() {
			if tensor.HasNonZeroTCPWindow() {
				return ScanStateOpen
			}
			return ScanStateClosed
		}
		if tensor.IsTCPFiltered() {
			return ScanStateFiltered
		}
	case ScanKindUDP:
		if tensor.IsUDPStateOpen() {
			return ScanStateOpen
		}
		if tensor.IsUDPStateClosed() {
			return ScanStateClosed
		}
		if tensor.IsUDPFiltered() {
			return ScanStateFiltered
		}
	}

	return ScanStateUnknown
}
