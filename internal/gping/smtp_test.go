package gping

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunSMTPBasicConfirmAddsClaimsAndRecommendation(t *testing.T) {
	listener := startFakeSMTPServer(t, smtpServerConfig{
		Banner:    "220 mx1.example.net ESMTP Postfix",
		EHLOLines: []string{"250-mx1.example.net", "250-PIPELINING", "250 STARTTLS"},
		EnableTLS: true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template smtp/basic-confirm",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "smtp/basic-confirm",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	report := result.Reports[0]
	if report.RawStatus != "220" {
		t.Fatalf("unexpected smtp banner status: got %q want 220", report.RawStatus)
	}
	if !hasClaim(report, "service", "name", "smtp") {
		t.Fatalf("expected service.name=smtp claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "smtp", "response_code", "220") {
		t.Fatalf("expected smtp.response_code claim, got %+v", report.Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func TestRunSMTPEnrichAddsEHLOAndSTARTTLSClaims(t *testing.T) {
	listener := startFakeSMTPServer(t, smtpServerConfig{
		Banner:    "220 mx1.example.net ESMTP Postfix",
		EHLOLines: []string{"250-mx1.example.net", "250-PIPELINING", "250-8BITMIME", "250 STARTTLS"},
		EnableTLS: true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:        "goscan gping --ip 127.0.0.1 --port test --template uam/smtp-enrich --insecure",
		IP:                 "127.0.0.1",
		Port:               port,
		TemplateName:       "uam/smtp-enrich",
		InsecureSkipVerify: true,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 3 {
		t.Fatalf("unexpected report count: got %d want 3", len(result.Reports))
	}
	if !hasClaim(result.Reports[1], "smtp", "ehlo_ok", "true") {
		t.Fatalf("expected smtp.ehlo_ok claim, got %+v", result.Reports[1].Claims)
	}
	if !hasJSONClaim(result.Reports[1], "smtp", "capabilities") {
		t.Fatalf("expected smtp.capabilities JSON claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[2], "smtp", "starttls_ok", "true") {
		t.Fatalf("expected smtp.starttls_ok claim, got %+v", result.Reports[2].Claims)
	}
	if !hasClaimPrefix(result.Reports[2], "tls", "subject", "CN=db.internal") {
		t.Fatalf("expected tls.subject from STARTTLS certificate, got %+v", result.Reports[2].Claims)
	}
}

type smtpServerConfig struct {
	Banner    string
	EHLOLines []string
	EnableTLS bool
}

func startFakeSMTPServer(t *testing.T, cfg smtpServerConfig) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	tlsConfig := testTLSConfig(t)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				io.WriteString(conn, cfg.Banner+"\r\n")

				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
					for _, reply := range cfg.EHLOLines {
						io.WriteString(conn, reply+"\r\n")
					}
				}

				line, err = reader.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if !cfg.EnableTLS || !strings.EqualFold(line, "STARTTLS") {
					return
				}
				io.WriteString(conn, "220 ready for TLS\r\n")
				tlsConn := tls.Server(conn, tlsConfig)
				_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	return listener
}
