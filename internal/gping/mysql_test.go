package gping

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunMySQLBasicConfirmAddsExtractClaimsAndRecommendation(t *testing.T) {
	listener := startFakeMySQLServer(t, fakeMySQLServerConfig{
		ServerVersion: "8.0.36",
		AuthPlugin:    "caching_sha2_password",
		SSL:           true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template mysql/basic-confirm",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "mysql/basic-confirm",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	report := result.Reports[0]
	if report.RawStatus != "success" {
		t.Fatalf("unexpected mysql status: got %q want success", report.RawStatus)
	}
	if !hasClaim(report, "service", "name", "mysql") {
		t.Fatalf("expected service.name=mysql claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "service", "version", "8.0.36") {
		t.Fatalf("expected service.version=8.0.36 claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "mysql", "protocol_version", "10") {
		t.Fatalf("expected mysql.protocol_version=10 claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "mysql", "auth_plugin", "caching_sha2_password") {
		t.Fatalf("expected mysql.auth_plugin claim, got %+v", report.Claims)
	}
	if !hasJSONClaim(report, "mysql", "capabilities") {
		t.Fatalf("expected mysql.capabilities JSON claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "mysql", "server_flavor", "mysql_like") {
		t.Fatalf("expected mysql.server_flavor=mysql_like extract claim, got %+v", report.Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func TestRunMySQLStartTLSEmitsTLSClaims(t *testing.T) {
	listener := startFakeMySQLServer(t, fakeMySQLServerConfig{
		ServerVersion: "8.0.36",
		AuthPlugin:    "caching_sha2_password",
		SSL:           true,
		EnableTLS:     true,
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:        "goscan gping --ip 127.0.0.1 --port test --method mysql-starttls",
		IP:                 "127.0.0.1",
		Port:               port,
		Route:              "app",
		Method:             "mysql-starttls",
		InsecureSkipVerify: true,
		Timeout:            2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	report := result.Reports[0]
	if report.RawStatus != "success" {
		t.Fatalf("unexpected mysql-starttls status: got %q want success", report.RawStatus)
	}
	if !hasClaim(report, "mysql", "ssl_handshake_ok", "true") {
		t.Fatalf("expected mysql.ssl_handshake_ok=true claim, got %+v", report.Claims)
	}
	if !hasClaimPrefix(report, "tls", "subject", "CN=db.internal") {
		t.Fatalf("expected tls.subject claim with db.internal CN, got %+v", report.Claims)
	}
}

type fakeMySQLServerConfig struct {
	ServerVersion string
	AuthPlugin    string
	SSL           bool
	EnableTLS     bool
}

func startFakeMySQLServer(t *testing.T, cfg fakeMySQLServerConfig) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}

	var tlsConfig *tls.Config
	if cfg.EnableTLS {
		tlsConfig = testTLSConfig(t)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if err := writeMySQLPacket(conn, 0, fakeMySQLGreetingPayload(cfg)); err != nil {
					return
				}
				if !cfg.EnableTLS {
					return
				}

				if _, _, err := readMySQLPacket(conn); err != nil {
					return
				}

				serverTLS := tls.Server(conn, tlsConfig)
				_ = serverTLS.SetDeadline(time.Now().Add(3 * time.Second))
				_ = serverTLS.Handshake()
				_ = serverTLS.Close()
			}(conn)
		}
	}()

	return listener
}

func fakeMySQLGreetingPayload(cfg fakeMySQLServerConfig) []byte {
	serverVersion := cfg.ServerVersion
	if serverVersion == "" {
		serverVersion = "8.0.36"
	}
	authPlugin := cfg.AuthPlugin
	if authPlugin == "" {
		authPlugin = "caching_sha2_password"
	}

	flags := mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth
	if cfg.SSL {
		flags |= mysqlClientSSL
	}

	payload := make([]byte, 0, 128)
	payload = append(payload, 0x0a)
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, 0x00)

	connectionID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connectionID, 1234)
	payload = append(payload, connectionID...)
	payload = append(payload, []byte("abcdefgh")...)
	payload = append(payload, 0x00)

	lowerFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(lowerFlags, uint16(flags&0xffff))
	payload = append(payload, lowerFlags...)
	payload = append(payload, 0x21) // utf8_general_ci
	payload = append(payload, 0x02, 0x00)

	upperFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(upperFlags, uint16(flags>>16))
	payload = append(payload, upperFlags...)
	payload = append(payload, byte(len(authPlugin)+1))
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, []byte("ijklmnopqrstuv")...)
	payload = append(payload, 0x00)
	payload = append(payload, []byte(authPlugin)...)
	payload = append(payload, 0x00)
	return payload
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "db.internal",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"db.internal"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate returned error: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair returned error: %v", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{certificate}}
}

func hasJSONClaim(report ExecutionReport, namespace string, name string) bool {
	for _, item := range report.Claims {
		if item.Namespace == namespace && item.Name == name && strings.TrimSpace(item.ValueJSON) != "" {
			return true
		}
	}
	return false
}

func hasClaimPrefix(report ExecutionReport, namespace string, name string, prefix string) bool {
	for _, item := range report.Claims {
		if item.Namespace == namespace && item.Name == name && strings.HasPrefix(item.ValueText, prefix) {
			return true
		}
	}
	return false
}
