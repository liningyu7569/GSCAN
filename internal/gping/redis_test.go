package gping

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunRedisBasicConfirmAddsClaimsAndRecommendation(t *testing.T) {
	listener := startFakeRedisServer(t, fakeRedisServerConfig{
		PingReply:       "+PONG\r\n",
		InfoServer:      redisBulkString("# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n"),
		InfoReplication: redisBulkString("# Replication\r\nrole:master\r\n\r\n"),
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template redis/basic-confirm",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "redis/basic-confirm",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 1 {
		t.Fatalf("unexpected report count: got %d want 1", len(result.Reports))
	}
	report := result.Reports[0]
	if report.RawStatus != "PONG" {
		t.Fatalf("unexpected redis ping status: got %q want PONG", report.RawStatus)
	}
	if !hasClaim(report, "service", "name", "redis") {
		t.Fatalf("expected service.name=redis claim, got %+v", report.Claims)
	}
	if !hasClaim(report, "redis", "ping_ok", "true") {
		t.Fatalf("expected redis.ping_ok=true claim, got %+v", report.Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func TestRunRedisEnrichAddsInfoClaims(t *testing.T) {
	listener := startFakeRedisServer(t, fakeRedisServerConfig{
		PingReply:       "+PONG\r\n",
		InfoServer:      redisBulkString("# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n"),
		InfoReplication: redisBulkString("# Replication\r\nrole:master\r\n\r\n"),
	})
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template uam/redis-enrich",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "uam/redis-enrich",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 3 {
		t.Fatalf("unexpected report count: got %d want 3", len(result.Reports))
	}
	if !hasClaim(result.Reports[1], "service", "version", "7.2.4") {
		t.Fatalf("expected service.version from INFO server, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[1], "redis", "mode", "standalone") {
		t.Fatalf("expected redis.mode claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[2], "redis", "role", "master") {
		t.Fatalf("expected redis.role claim, got %+v", result.Reports[2].Claims)
	}
	if !hasClaim(result.Reports[1], "redis", "info_accessible", "true") {
		t.Fatalf("expected redis.info_accessible extract claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[2], "redis", "replication_info_accessible", "true") {
		t.Fatalf("expected redis.replication_info_accessible extract claim, got %+v", result.Reports[2].Claims)
	}
}

type fakeRedisServerConfig struct {
	PingReply       string
	InfoServer      string
	InfoReplication string
}

func startFakeRedisServer(t *testing.T, cfg fakeRedisServerConfig) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
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
				reader := bufio.NewReader(conn)
				command, args, err := readRESPArrayForTest(reader)
				if err != nil {
					return
				}
				switch strings.ToUpper(command) {
				case "PING":
					io.WriteString(conn, cfg.PingReply)
				case "INFO":
					section := ""
					if len(args) > 0 {
						section = strings.ToLower(args[0])
					}
					switch section {
					case "server":
						io.WriteString(conn, cfg.InfoServer)
					case "replication":
						io.WriteString(conn, cfg.InfoReplication)
					default:
						io.WriteString(conn, "-ERR unknown INFO section\r\n")
					}
				default:
					io.WriteString(conn, "-ERR unknown command\r\n")
				}
			}(conn)
		}
	}()

	return listener
}

func readRESPArrayForTest(reader *bufio.Reader) (string, []string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "*") {
		return "", nil, fmt.Errorf("expected RESP array")
	}
	var count int
	fmt.Sscanf(line, "*%d", &count)
	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		sizeLine = strings.TrimSpace(sizeLine)
		if !strings.HasPrefix(sizeLine, "$") {
			return "", nil, fmt.Errorf("expected RESP bulk size")
		}
		var size int
		fmt.Sscanf(sizeLine, "$%d", &size)
		body := make([]byte, size+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			return "", nil, err
		}
		parts = append(parts, string(body[:size]))
	}
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty RESP array")
	}
	return parts[0], parts[1:], nil
}

func redisBulkString(value string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}
