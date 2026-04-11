package l7

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSelectCandidateProbesUsesSSLPortsAndFallbacks(t *testing.T) {
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP NULL q||",
		"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|",
		"Probe TCP SSLSessionReq q|\\x16\\x03\\x00|",
		"sslports 443",
		"fallback GetRequest",
		"Probe TCP GenericLines q|\\r\\n\\r\\n|",
	}, "\n"))

	probes := selectCandidateProbes(443, syscall.IPPROTO_TCP)
	if got := probeNames(probes); strings.Join(got, ",") != "NULL,SSLSessionReq,GetRequest" {
		t.Fatalf("unexpected tcp candidates: got %v", got)
	}
}

func TestSelectCandidateProbesUsesTCPGenericFallbacksOnlyWhenNeeded(t *testing.T) {
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP NULL q||",
		"Probe TCP GenericLines q|\\r\\n\\r\\n|",
		"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|",
	}, "\n"))

	probes := selectCandidateProbes(65000, syscall.IPPROTO_TCP)
	if got := probeNames(probes); strings.Join(got, ",") != "NULL,GenericLines,GetRequest" {
		t.Fatalf("unexpected generic tcp candidates: got %v", got)
	}
}

func TestSelectCandidateProbesForUDPSkipsTCPCommonProbes(t *testing.T) {
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP NULL q||",
		"Probe UDP DNSVersionBindReq q|PING|",
		"ports 53",
	}, "\n"))

	probes := selectCandidateProbes(53, syscall.IPPROTO_UDP)
	if got := probeNames(probes); strings.Join(got, ",") != "DNSVersionBindReq" {
		t.Fatalf("unexpected udp candidates: got %v", got)
	}
}

func TestSelectCandidateProbesOrdersByRarityAndSpecificity(t *testing.T) {
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP NULL q||",
		"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|",
		"rarity 5",
		"sslports 443",
		"Probe TCP TLSSessionReq q|\\x16\\x03\\x01|",
		"rarity 1",
		"ports 443",
		"Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\\r\\n\\r\\n|",
		"rarity 4",
		"ports 443",
		"fallback GetRequest",
	}, "\n"))

	probes := selectCandidateProbes(443, syscall.IPPROTO_TCP)
	if got := probeNames(probes); strings.Join(got, ",") != "NULL,TLSSessionReq,HTTPOptions,GetRequest" {
		t.Fatalf("unexpected ordered tcp candidates: got %v", got)
	}
}

func TestIdentifyServiceTCPWithGenericFallback(t *testing.T) {
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP NULL q||",
		"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|",
		"match http m|^HTTP/1\\.1 200 OK\\r\\nServer: ([^\\r\\n]+)| p/$1/",
		"Probe TCP GenericLines q|\\r\\n\\r\\n|",
	}, "\n"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))

				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if strings.HasPrefix(string(buf[:n]), "GET / HTTP/1.0") {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: test-http\r\n\r\n"))
				}
			}(conn)
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	buffer := make([]byte, 4096)
	fp := IdentifyService("127.0.0.1", port, syscall.IPPROTO_TCP, &buffer)
	if fp.Service != "http" {
		t.Fatalf("unexpected service: got %q want http", fp.Service)
	}
	if fp.Banner != "test-http" {
		t.Fatalf("unexpected banner: got %q want test-http", fp.Banner)
	}
}

func TestIdentifyServiceUDPWithTargetedProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	defer pc.Close()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	loadTestProbeSet(t, strings.Join([]string{
		fmt.Sprintf("Probe UDP DNSVersionBindReq q|PING|"),
		fmt.Sprintf("ports %d", port),
		"match domain m|^version\\.bind| p/bind/",
	}, "\n"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "PING" {
			_, _ = pc.WriteTo([]byte("version.bind"), addr)
		}
	}()

	buffer := make([]byte, 4096)
	fp := IdentifyService("127.0.0.1", uint16(port), syscall.IPPROTO_UDP, &buffer)
	<-done
	if fp.Service != "domain" {
		t.Fatalf("unexpected udp service: got %q want domain", fp.Service)
	}
	if fp.Banner != "bind" {
		t.Fatalf("unexpected udp banner: got %q want bind", fp.Banner)
	}
}

func TestIdentifyServiceAccumulatesSplitTCPResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	loadTestProbeSet(t, strings.Join([]string{
		"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|",
		fmt.Sprintf("ports %d", port),
		"totalwaitms 600",
		"match http m|^HTTP/1\\.1 200 OK\\r\\nServer: ([^\\r\\n]+)\\r\\n\\r\\n| p/$1/",
	}, "\n"))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if !strings.HasPrefix(string(buf[:n]), "GET / HTTP/1.0") {
					return
				}

				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: split"))
				time.Sleep(100 * time.Millisecond)
				_, _ = conn.Write([]byte("-server\r\n\r\n"))
			}(conn)
		}
	}()

	buffer := make([]byte, 4096)
	fp := IdentifyService("127.0.0.1", uint16(port), syscall.IPPROTO_TCP, &buffer)
	if fp.Service != "http" {
		t.Fatalf("unexpected service: got %q want http", fp.Service)
	}
	if fp.Product != "split-server" {
		t.Fatalf("unexpected product: got %q want split-server", fp.Product)
	}
	if fp.Banner != "split-server" {
		t.Fatalf("unexpected banner: got %q want split-server", fp.Banner)
	}
}

func TestParseVersionInfoSupportsAlternateDelimitersAndCPE(t *testing.T) {
	rule := MatchRule{}
	parseVersionInfo(&rule, `p|Demo Service| v/1.2.3/ i|alpha build| h%edge/node% o|z/OS| d=router/controller= cpe:/a:acme:demo_service:1.2.3/`)

	if rule.Product != "Demo Service" {
		t.Fatalf("unexpected product template: %q", rule.Product)
	}
	if rule.Version != "1.2.3" {
		t.Fatalf("unexpected version template: %q", rule.Version)
	}
	if rule.Info != "alpha build" || rule.Hostname != "edge/node" || rule.OS != "z/OS" || rule.Device != "router/controller" {
		t.Fatalf("unexpected parsed metadata: %+v", rule)
	}
	if len(rule.CPEs) != 1 || rule.CPEs[0] != "a:acme:demo_service:1.2.3" {
		t.Fatalf("unexpected cpe templates: %+v", rule.CPEs)
	}
}

func TestBuildFingerprintFromRuleSupportsMacros(t *testing.T) {
	rule := MatchRule{
		Service:  "demo",
		Product:  `Demo-$P(2)`,
		Version:  `$SUBST(2,"_",".")`,
		Info:     `ord $I(1,">")`,
		Hostname: `edge/node`,
		OS:       `z/OS`,
		Device:   `gateway`,
		CPEs:     []string{`a:acme:demo:$SUBST(2,"_",".")`},
	}

	groups := [][]byte{
		nil,
		{0x00, 0x2a},
		[]byte("ver_1"),
	}

	fp := buildFingerprintFromRule(rule, groups, nil)
	if fp.Product != "Demo-ver_1" {
		t.Fatalf("unexpected product: %q", fp.Product)
	}
	if fp.Version != "ver.1" {
		t.Fatalf("unexpected version: %q", fp.Version)
	}
	if fp.Info != "ord 42" {
		t.Fatalf("unexpected info: %q", fp.Info)
	}
	if fp.Hostname != "edge/node" || fp.OS != "z/OS" || fp.Device != "gateway" {
		t.Fatalf("unexpected fingerprint metadata: %+v", fp)
	}
	if len(fp.CPEs) != 1 || fp.CPEs[0] != "a:acme:demo:ver.1" {
		t.Fatalf("unexpected cpes: %+v", fp.CPEs)
	}
	if fp.Banner != "Demo-ver_1 ver.1 (ord 42)" {
		t.Fatalf("unexpected banner: %q", fp.Banner)
	}
}

func loadTestProbeSet(t *testing.T, raw string) {
	t.Helper()
	resetProbeRegistry()
	loadNmapProbes(raw)
	buildPortIndex()
	CacheCommonProbes()
}

func probeNames(probes []*Probe) []string {
	names := make([]string, 0, len(probes))
	for _, probe := range probes {
		names = append(names, probe.Name)
	}
	return names
}
