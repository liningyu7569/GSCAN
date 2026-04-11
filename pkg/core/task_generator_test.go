package core

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/queue"
	"Going_Scan/pkg/target"
	"net"
	"reflect"
	"syscall"
	"testing"
)

func TestTaskGeneratorGeneratesMultipleProtocolTasks(t *testing.T) {
	withCoreGlobalOps(t, func() {
		conf.GlobalOps.SkipHostDiscovery = true
		HDReservoir = queue.NewLockFreeRingBuffer[uint32](65536)

		iter, err := target.NewContainer([]string{"192.168.1.10"}, nil, false)
		if err != nil {
			t.Fatalf("NewContainer returned error: %v", err)
		}

		gen := NewTaskGenerator(iter, []int{53, 80}, []ScanProfile{
			{Name: "tcp-syn", Protocol: syscall.IPPROTO_TCP, ScanFlags: FlagSYN, ScanKind: ScanKindTCPSYN},
			{Name: "udp", Protocol: syscall.IPPROTO_UDP, ScanKind: ScanKindUDP},
		})
		gen.routeResolver = func(net.IP) (uint16, error) { return 3, nil }

		tasks, done := gen.GenerateBatch()
		if done {
			t.Fatal("expected one batch of scan tasks")
		}
		if len(tasks) != 4 {
			t.Fatalf("unexpected task count: got %d want 4", len(tasks))
		}

		got := []EmissionTask{
			{TargetPort: tasks[0].TargetPort, RouteID: tasks[0].RouteID, Protocol: tasks[0].Protocol, ScanFlags: tasks[0].ScanFlags, ScanKind: tasks[0].ScanKind},
			{TargetPort: tasks[1].TargetPort, RouteID: tasks[1].RouteID, Protocol: tasks[1].Protocol, ScanFlags: tasks[1].ScanFlags, ScanKind: tasks[1].ScanKind},
			{TargetPort: tasks[2].TargetPort, RouteID: tasks[2].RouteID, Protocol: tasks[2].Protocol, ScanFlags: tasks[2].ScanFlags, ScanKind: tasks[2].ScanKind},
			{TargetPort: tasks[3].TargetPort, RouteID: tasks[3].RouteID, Protocol: tasks[3].Protocol, ScanFlags: tasks[3].ScanFlags, ScanKind: tasks[3].ScanKind},
		}
		want := []EmissionTask{
			{TargetPort: 53, RouteID: 3, Protocol: syscall.IPPROTO_TCP, ScanFlags: FlagSYN, ScanKind: ScanKindTCPSYN},
			{TargetPort: 53, RouteID: 3, Protocol: syscall.IPPROTO_UDP, ScanFlags: 0, ScanKind: ScanKindUDP},
			{TargetPort: 80, RouteID: 3, Protocol: syscall.IPPROTO_TCP, ScanFlags: FlagSYN, ScanKind: ScanKindTCPSYN},
			{TargetPort: 80, RouteID: 3, Protocol: syscall.IPPROTO_UDP, ScanFlags: 0, ScanKind: ScanKindUDP},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected task batch: got %#v want %#v", got, want)
		}
	})
}

func TestTaskGeneratorSkipsTargetsWithRouteErrors(t *testing.T) {
	withCoreGlobalOps(t, func() {
		conf.GlobalOps.SkipHostDiscovery = true
		HDReservoir = queue.NewLockFreeRingBuffer[uint32](65536)

		iter, err := target.NewContainer([]string{"192.168.1.10", "192.168.1.11"}, nil, false)
		if err != nil {
			t.Fatalf("NewContainer returned error: %v", err)
		}

		gen := NewTaskGenerator(iter, []int{80}, nil)
		gen.routeResolver = func(ip net.IP) (uint16, error) {
			if ip.String() == "192.168.1.10" {
				return 0, syscall.EHOSTUNREACH
			}
			return 5, nil
		}

		tasks, done := gen.GenerateBatch()
		if done {
			t.Fatal("expected batch after skipping unreachable target")
		}
		if len(tasks) != 1 {
			t.Fatalf("unexpected task count: got %d want 1", len(tasks))
		}
		if got := net.IPv4(byte(tasks[0].TargetIP>>24), byte(tasks[0].TargetIP>>16), byte(tasks[0].TargetIP>>8), byte(tasks[0].TargetIP)).String(); got != "192.168.1.11" {
			t.Fatalf("unexpected target IP: got %s want 192.168.1.11", got)
		}
	})
}

func TestTaskGeneratorBuildsDefaultHostDiscoveryTasks(t *testing.T) {
	withCoreGlobalOps(t, func() {
		conf.GlobalOps.SkipHostDiscovery = false
		HDReservoir = queue.NewLockFreeRingBuffer[uint32](65536)

		iter, err := target.NewContainer([]string{"192.168.1.20"}, nil, false)
		if err != nil {
			t.Fatalf("NewContainer returned error: %v", err)
		}

		gen := NewTaskGenerator(iter, []int{80}, nil)
		gen.routeResolver = func(net.IP) (uint16, error) { return 1, nil }

		tasks, done := gen.GenerateBatch()
		if done {
			t.Fatal("expected host discovery batch")
		}
		if len(tasks) != DefaultHostDiscoveryProfileCount() {
			t.Fatalf("unexpected discovery task count: got %d want %d", len(tasks), DefaultHostDiscoveryProfileCount())
		}
		if tasks[0].Protocol != syscall.IPPROTO_ICMP || tasks[0].TargetPort != 0 || !tasks[0].IsHostDiscovery {
			t.Fatalf("unexpected ICMP discovery task: %+v", tasks[0])
		}
		if tasks[1].Protocol != syscall.IPPROTO_TCP || tasks[1].TargetPort != DefaultHostDiscoveryTCPPort || tasks[1].ScanFlags != FlagSYN {
			t.Fatalf("unexpected TCP discovery task: %+v", tasks[1])
		}
	})
}

func withCoreGlobalOps(t *testing.T, fn func()) {
	t.Helper()
	saved := *conf.GlobalOps
	defer func() {
		*conf.GlobalOps = saved
	}()
	fn()
}
