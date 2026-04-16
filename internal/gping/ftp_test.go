package gping

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunFTPBasicConfirmAddsClaimsAndRecommendation(t *testing.T) {
	listener := startFakeFTPServer(t, ftpServerConfig{
		Banner:    "220 (vsFTPd 3.0.5)",
		Features:  []string{"AUTH TLS", "UTF8"},
		EnableTLS: true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template ftp/basic-confirm",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "ftp/basic-confirm",
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
		t.Fatalf("unexpected ftp banner status: got %q want 220", report.RawStatus)
	}
	if !hasClaim(report, "service", "name", "ftp") {
		t.Fatalf("expected service.name=ftp claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "ftp", "response_code", "220") {
		t.Fatalf("expected ftp.response_code claim, got %+v", report.Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func TestRunFTPEnrichAddsFeaturesAndAuthTLSClaims(t *testing.T) {
	listener := startFakeFTPServer(t, ftpServerConfig{
		Banner:    "220 FileZilla Server 1.8.0",
		Features:  []string{"AUTH TLS", "UTF8", "MLST"},
		EnableTLS: true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:        "goscan gping --ip 127.0.0.1 --port test --template uam/ftp-enrich --insecure",
		IP:                 "127.0.0.1",
		Port:               port,
		TemplateName:       "uam/ftp-enrich",
		InsecureSkipVerify: true,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 3 {
		t.Fatalf("unexpected report count: got %d want 3", len(result.Reports))
	}
	if !hasJSONClaim(result.Reports[1], "ftp", "features") {
		t.Fatalf("expected ftp.features JSON claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[1], "ftp", "command_ok", "true") {
		t.Fatalf("expected ftp.command_ok extract claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[2], "ftp", "auth_tls_ok", "true") {
		t.Fatalf("expected ftp.auth_tls_ok claim, got %+v", result.Reports[2].Claims)
	}
	if !hasClaimPrefix(result.Reports[2], "tls", "subject", "CN=db.internal") {
		t.Fatalf("expected tls.subject from AUTH TLS certificate, got %+v", result.Reports[2].Claims)
	}
}

type ftpServerConfig struct {
	Banner    string
	Features  []string
	EnableTLS bool
}

func startFakeFTPServer(t *testing.T, cfg ftpServerConfig) net.Listener {
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
				if !strings.EqualFold(line, "FEAT") {
					return
				}

				if len(cfg.Features) == 0 {
					io.WriteString(conn, "500 FEAT not understood\r\n")
					return
				}
				io.WriteString(conn, "211-Features:\r\n")
				for _, feature := range cfg.Features {
					io.WriteString(conn, fmt.Sprintf(" %s\r\n", feature))
				}
				io.WriteString(conn, "211 End\r\n")

				line, err = reader.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if !cfg.EnableTLS || !strings.EqualFold(line, "AUTH TLS") {
					return
				}
				io.WriteString(conn, "234 Proceed with negotiation.\r\n")
				tlsConn := tls.Server(conn, tlsConfig)
				_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	return listener
}
