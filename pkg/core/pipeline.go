package core

import (
	"Going_Scan/pkg/target"
	"net/netip"
	"time"
)

type SendTask struct {
	Target   *target.Target
	Protocol int
	Port     int
	Seq      uint32
	Ack      uint32
	Flags    uint8

	SrcIP  netip.Addr
	IsReal bool

	Payload []byte
}

type RecvEvent struct {
	SrcIP    string
	SrcPort  int
	Protocol int
	Flags    uint8
	RecvTime time.Time
	Seq      uint32
	Ack      uint32

	ICMPType uint8
	ICMPCode uint8
}
