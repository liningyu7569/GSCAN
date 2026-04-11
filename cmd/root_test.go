package cmd

import (
	"Going_Scan/pkg/conf"
	"Going_Scan/pkg/core"
	"reflect"
	"syscall"
	"testing"
)

func TestParsePortsSortsAndDeduplicates(t *testing.T) {
	ports, err := parsePorts("443,80,81-82,80")
	if err != nil {
		t.Fatalf("parsePorts returned error: %v", err)
	}

	want := []int{80, 81, 82, 443}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("unexpected ports: got %v want %v", ports, want)
	}
}

func TestResolvePortsRejectsConflicts(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.PortStr = "80"
		conf.GlobalOps.FastScan = true

		if _, _, err := resolvePorts(); err == nil {
			t.Fatal("expected resolvePorts to reject conflicting port inputs")
		}
	})
}

func TestResolvePortsUsesBundledTopPortsForFastMode(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.FastScan = true

		ports, _, err := resolvePorts()
		if err != nil {
			t.Fatalf("resolvePorts returned error: %v", err)
		}
		if !reflect.DeepEqual(ports, core.TopPorts) {
			t.Fatalf("unexpected fast-scan ports: got %v want %v", ports, core.TopPorts)
		}
	})
}

func TestResolveScanProfilesSupportsSynAndUDP(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.Synscan = true
		conf.GlobalOps.Udpscan = true

		profiles, err := resolveScanProfiles()
		if err != nil {
			t.Fatalf("resolveScanProfiles returned error: %v", err)
		}
		if len(profiles) != 2 {
			t.Fatalf("unexpected profile count: got %d want 2", len(profiles))
		}
		if profiles[0].Protocol != syscall.IPPROTO_TCP || profiles[0].ScanFlags != core.FlagSYN {
			t.Fatalf("unexpected TCP profile: %+v", profiles[0])
		}
		if profiles[0].ScanKind != core.ScanKindTCPSYN {
			t.Fatalf("unexpected TCP scan kind: %+v", profiles[0])
		}
		if profiles[1].Protocol != syscall.IPPROTO_UDP {
			t.Fatalf("unexpected UDP profile: %+v", profiles[1])
		}
		if profiles[1].ScanKind != core.ScanKindUDP {
			t.Fatalf("unexpected UDP scan kind: %+v", profiles[1])
		}
	})
}

func TestResolveScanProfilesSupportsAckAndWindow(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.Ackscan = true
		conf.GlobalOps.Windowscan = true

		profiles, err := resolveScanProfiles()
		if err != nil {
			t.Fatalf("resolveScanProfiles returned error: %v", err)
		}
		if len(profiles) != 2 {
			t.Fatalf("unexpected profile count: got %d want 2", len(profiles))
		}
		if profiles[0].ScanKind != core.ScanKindTCPACK || profiles[0].ScanFlags != core.FlagACK {
			t.Fatalf("unexpected ACK profile: %+v", profiles[0])
		}
		if profiles[1].ScanKind != core.ScanKindTCPWINDOW || profiles[1].ScanFlags != core.FlagACK {
			t.Fatalf("unexpected Window profile: %+v", profiles[1])
		}
	})
}

func TestValidateUnsupportedOptionsRejectsNoOpFlags(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.SourcePort = 12345

		if err := validateUnsupportedOptions(); err == nil {
			t.Fatal("expected unsupported option error")
		}
	})
}

func TestResolveOutputConfigInfersYamlFromExtension(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.OutputFile = "report.yaml"

		if err := resolveOutputConfig(); err != nil {
			t.Fatalf("resolveOutputConfig returned error: %v", err)
		}
		if !conf.GlobalOps.IsOutputFile {
			t.Fatal("expected output to be enabled")
		}
		if conf.GlobalOps.OutputFormat != "yaml" {
			t.Fatalf("unexpected output format: got %q want yaml", conf.GlobalOps.OutputFormat)
		}
	})
}

func TestResolveOutputConfigRejectsFormatWithoutFile(t *testing.T) {
	withGlobalOps(func() {
		conf.GlobalOps.OutputFormat = "json"

		if err := resolveOutputConfig(); err == nil {
			t.Fatal("expected resolveOutputConfig to reject format without file")
		}
	})
}

func withGlobalOps(fn func()) {
	saved := *conf.GlobalOps
	defer func() {
		*conf.GlobalOps = saved
	}()
	fn()
}
