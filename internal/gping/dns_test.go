package gping

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestLoadDNSTemplateAppliesTo(t *testing.T) {
	spec, err := LoadTemplate("dns/basic-confirm")
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}
	if spec.AppliesTo.Protocol != "" || len(spec.AppliesTo.Ports) != 0 || len(spec.AppliesTo.CurrentService) != 1 || spec.AppliesTo.CurrentService[0] != "dns" {
		t.Fatalf("unexpected applies_to: %+v", spec.AppliesTo)
	}
}

func TestRunDNSBasicConfirmAddsClaimsAndRecommendation(t *testing.T) {
	conn := startFakeDNSServer(t, dnsServerConfig{
		AnswerIP: "93.184.216.34",
		RA:       true,
		AA:       false,
		RCode:    0,
	})
	defer conn.Close()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --protocol udp --template dns/basic-confirm",
		IP:           "127.0.0.1",
		Port:         port,
		Protocol:     "udp",
		TemplateName: "dns/basic-confirm",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	report := result.Reports[0]
	if report.RawStatus != "NOERROR" {
		t.Fatalf("unexpected dns status: got %q want NOERROR", report.RawStatus)
	}
	if !hasClaim(report, "service", "name", "dns") {
		t.Fatalf("expected service.name=dns claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "dns", "rcode", "NOERROR") {
		t.Fatalf("expected dns.rcode claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "dns", "answer_count", "1") {
		t.Fatalf("expected dns.answer_count claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "dns", "recursion_available", "true") {
		t.Fatalf("expected dns.recursion_available claim, got %+v", report.Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func TestRunDNSEnrichAddsResponseRoleExtract(t *testing.T) {
	conn := startFakeDNSServer(t, dnsServerConfig{
		AnswerIP: "93.184.216.34",
		RA:       false,
		AA:       true,
		RCode:    0,
	})
	defer conn.Close()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --protocol udp --template uam/dns-enrich",
		IP:           "127.0.0.1",
		Port:         port,
		Protocol:     "udp",
		TemplateName: "uam/dns-enrich",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	if !hasClaim(result.Reports[0], "dns", "response_role", "authoritative_like") {
		t.Fatalf("expected dns.response_role extract claim, got %+v", result.Reports[0].Claims)
	}
}

type dnsServerConfig struct {
	AnswerIP string
	RA       bool
	AA       bool
	RCode    int
}

func startFakeDNSServer(t *testing.T, cfg dnsServerConfig) *net.UDPConn {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr returned error: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP returned error: %v", err)
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			response, err := buildFakeDNSResponse(query, cfg)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(response, remote)
		}
	}()

	return conn
}

func buildFakeDNSResponse(query []byte, cfg dnsServerConfig) ([]byte, error) {
	if len(query) < 12 {
		return nil, net.InvalidAddrError("query too short")
	}
	offset := 12
	nameEnd, err := skipDNSName(query, offset)
	if err != nil {
		return nil, err
	}
	if nameEnd+4 > len(query) {
		return nil, net.InvalidAddrError("question too short")
	}
	question := append([]byte(nil), query[12:nameEnd+4]...)

	response := make([]byte, 12)
	copy(response[0:2], query[0:2])
	flags := uint16(0x8000)
	flags |= uint16(cfg.RCode & 0x0f)
	if cfg.AA {
		flags |= 1 << 10
	}
	if cfg.RA {
		flags |= 1 << 7
	}
	if query[2]&(1<<0) != 0 {
		flags |= 1 << 8
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	if cfg.RCode == 0 {
		binary.BigEndian.PutUint16(response[6:8], 1)
	} else {
		binary.BigEndian.PutUint16(response[6:8], 0)
	}
	response = append(response, question...)
	if cfg.RCode == 0 {
		answer := buildFakeDNSAnswer(cfg.AnswerIP)
		response = append(response, answer...)
	}
	return response, nil
}

func buildFakeDNSAnswer(ip string) []byte {
	value := net.ParseIP(ip).To4()
	answer := []byte{0xc0, 0x0c}
	buf := make([]byte, 10)
	binary.BigEndian.PutUint16(buf[0:2], 1)
	binary.BigEndian.PutUint16(buf[2:4], 1)
	binary.BigEndian.PutUint32(buf[4:8], 60)
	binary.BigEndian.PutUint16(buf[8:10], 4)
	answer = append(answer, buf...)
	answer = append(answer, value...)
	return answer
}
