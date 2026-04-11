package core

import "syscall"

// ScanProfile describes one concrete L4 scan mode that can be emitted for a port.
type ScanProfile struct {
	Name      string
	Protocol  uint8
	ScanFlags uint8
	ScanKind  uint8
}

const DefaultHostDiscoveryTCPPort uint16 = 80

var defaultPortScanProfiles = []ScanProfile{
	{Name: "tcp-syn", Protocol: syscall.IPPROTO_TCP, ScanFlags: FlagSYN, ScanKind: ScanKindTCPSYN},
}

var defaultHostDiscoveryProfiles = []ScanProfile{
	{Name: "icmp-echo", Protocol: syscall.IPPROTO_ICMP},
	{Name: "tcp-syn-ping", Protocol: syscall.IPPROTO_TCP, ScanFlags: FlagSYN, ScanKind: ScanKindTCPSYN},
}

func DefaultPortScanProfiles() []ScanProfile {
	return append([]ScanProfile(nil), defaultPortScanProfiles...)
}

func DefaultHostDiscoveryProfiles() []ScanProfile {
	return append([]ScanProfile(nil), defaultHostDiscoveryProfiles...)
}

func DefaultHostDiscoveryProfileCount() int {
	return len(defaultHostDiscoveryProfiles)
}
