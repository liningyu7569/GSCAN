package gping

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// redisAdapter Redis 协议适配器，支持 PING、INFO 命令
type redisAdapter struct{}

// Name 返回适配器名称
func (redisAdapter) Name() string { return "redis" }

// Capabilities 返回 Redis 适配器支持的能力
func (redisAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportedMethods: []string{"redis-ping", "redis-info-server", "redis-info-replication"},
	}
}

// Execute 执行 Redis 命令并返回结构化结果
func (redisAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	switch normalizeMethod(req.Method) {
	case "redis-ping":
		return executeRedisPing(ctx, req)
	case "redis-info-server":
		return executeRedisInfo(ctx, req, "server")
	case "redis-info-replication":
		return executeRedisInfo(ctx, req, "replication")
	default:
		return AppResult{}, fmt.Errorf("unsupported redis method %q", req.Method)
	}
}

func executeRedisPing(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, reader, _, err := openRedisConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "PING",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	if err := writeRESPArray(conn, "PING"); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "PING",
			ErrorText:      err.Error(),
		}, nil
	}

	reply, err := readRESPReply(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "PING",
			ErrorText:      err.Error(),
		}, nil
	}

	fields := map[string]any{}
	extra := map[string]any{}
	rawStatus := reply.Status()
	responseSummary := reply.Summary()
	switch reply.Kind {
	case redisReplySimple:
		fields["ping_ok"] = strings.EqualFold(reply.Text, "PONG")
		fields["auth_required"] = false
		extra["ping_ok"] = strings.EqualFold(reply.Text, "PONG")
	case redisReplyError:
		authRequired := isRedisAuthError(reply.Text)
		fields["ping_ok"] = false
		fields["auth_required"] = authRequired
		extra["error"] = reply.Text
	case redisReplyBulk:
		fields["ping_ok"] = false
		fields["auth_required"] = false
		extra["bulk"] = reply.Text
	default:
		fields["ping_ok"] = false
		fields["auth_required"] = false
	}

	return AppResult{
		RawStatus:       rawStatus,
		RequestSummary:  "PING",
		ResponseSummary: responseSummary,
		RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeRedisInfo(ctx context.Context, req AppRequest, section string) (AppResult, error) {
	conn, reader, _, err := openRedisConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("INFO %s", section),
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	if err := writeRESPArray(conn, "INFO", section); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("INFO %s", section),
			ErrorText:      err.Error(),
		}, nil
	}

	reply, err := readRESPReply(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("INFO %s", section),
			ErrorText:      err.Error(),
		}, nil
	}

	fields := map[string]any{
		"auth_required": false,
	}
	extra := map[string]any{
		"section": section,
	}
	rawStatus := reply.Status()
	responseSummary := reply.Summary()

	switch reply.Kind {
	case redisReplyBulk:
		info := parseRedisInfo(reply.Text)
		extra["info"] = info
		fields["info_accessible"] = true
		if section == "server" {
			if version := stringAny(info["redis_version"]); version != "" {
				fields["redis_version"] = version
				fields["version"] = version
			}
			if mode := stringAny(info["redis_mode"]); mode != "" {
				fields["redis_mode"] = mode
			}
			fields["info_server_accessible"] = true
			responseSummary = strings.TrimSpace(strings.Join([]string{
				summaryPart("version", stringAny(info["redis_version"])),
				summaryPart("mode", stringAny(info["redis_mode"])),
			}, " "))
		}
		if section == "replication" {
			if role := stringAny(info["role"]); role != "" {
				fields["role"] = role
			}
			fields["info_replication_accessible"] = true
			responseSummary = strings.TrimSpace(strings.Join([]string{
				summaryPart("role", stringAny(info["role"])),
				summaryPart("replicas", stringAny(info["connected_slaves"])),
			}, " "))
		}
	case redisReplyError:
		authRequired := isRedisAuthError(reply.Text)
		fields["auth_required"] = authRequired
		fields["info_accessible"] = false
		if section == "server" {
			fields["info_server_accessible"] = false
		}
		if section == "replication" {
			fields["info_replication_accessible"] = false
		}
		extra["error"] = reply.Text
	default:
		fields["info_accessible"] = false
	}

	return AppResult{
		RawStatus:       rawStatus,
		RequestSummary:  fmt.Sprintf("INFO %s", section),
		ResponseSummary: responseSummary,
		RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func openRedisConn(ctx context.Context, req AppRequest) (net.Conn, *bufio.Reader, *float64, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, bufio.NewReader(conn), floatPtrValue(time.Since(start).Seconds() * 1000), nil
}

func writeRESPArray(conn net.Conn, parts ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, part := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(part), part)
	}
	_, err := io.WriteString(conn, b.String())
	return err
}

// redisReplyKind 表示 Redis RESP 回复类型
type redisReplyKind string

const (
	redisReplySimple redisReplyKind = "simple"
	redisReplyError  redisReplyKind = "error"
	redisReplyBulk   redisReplyKind = "bulk"
)

// redisReply 解析后的 Redis RESP 回复
type redisReply struct {
	Kind redisReplyKind
	Text string
}

func (r redisReply) Status() string {
	switch r.Kind {
	case redisReplySimple:
		return strings.TrimSpace(r.Text)
	case redisReplyError:
		text := strings.TrimSpace(r.Text)
		if text == "" {
			return "error"
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return "error"
		}
		return fields[0]
	case redisReplyBulk:
		return "success"
	default:
		return "error"
	}
}

func (r redisReply) Summary() string {
	switch r.Kind {
	case redisReplyBulk:
		return previewText(strings.TrimSpace(firstLine(r.Text)), 120)
	default:
		return strings.TrimSpace(r.Text)
	}
}

func readRESPReply(reader *bufio.Reader) (redisReply, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return redisReply{}, err
	}

	switch prefix {
	case '+':
		line, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		return redisReply{Kind: redisReplySimple, Text: line}, nil
	case '-':
		line, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		return redisReply{Kind: redisReplyError, Text: line}, nil
	case '$':
		line, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		length, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return redisReply{}, err
		}
		if length < 0 {
			return redisReply{Kind: redisReplyBulk, Text: ""}, nil
		}
		body := make([]byte, length+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			return redisReply{}, err
		}
		return redisReply{Kind: redisReplyBulk, Text: string(body[:length])}, nil
	default:
		return redisReply{}, fmt.Errorf("unsupported RESP prefix %q", prefix)
	}
}

func readRESPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func parseRedisInfo(raw string) map[string]string {
	out := make(map[string]string)
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func isRedisAuthError(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	return strings.Contains(lower, "noauth") || strings.Contains(lower, "noperm")
}
