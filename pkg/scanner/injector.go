package scanner

import (
	"fmt"
	"github.com/google/gopacket/pcap"
)

type PacketInjector struct {
	TaskChan <-chan SendTask
	Handle   *pcap.Handle
}

func NewInjector(ch <-chan SendTask, handle *pcap.Handle) *PacketInjector {
	return &PacketInjector{
		TaskChan: ch,
		Handle:   handle,
	}
}

func (inj *PacketInjector) Run() {
	for task := range inj.TaskChan {

		rawBytes, err := ConstructRawPacket(task)
		if err != nil {
			fmt.Printf("Error constructing raw packet: %v for Protocol : %d \n", err, task.Protocol)
			continue
		}
		fmt.Println(rawBytes)
		if err := inj.Handle.WritePacketData(rawBytes); err != nil {
			fmt.Printf("Error writing raw packet: %v\n", err)
		}

	}
}

// 构建包
func constructRawPacket(task SendTask) []byte {
	return []byte{}
}
