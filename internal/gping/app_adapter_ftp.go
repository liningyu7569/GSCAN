package gping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type ftpAdapter struct{}

type ftpReply struct {
	Code  int
	Line  string
	Lines []string
}

func (ftpAdapter) Name() string { return "ftp" }

func (ftpAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportsTLS:      true,
		SupportedMethods: []string{"ftp-banner", "ftp-feat", "ftp-auth-tls"},
	}
}

func (ftpAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	switch normalizeMethod(req.Method) {
	case "ftp-banner":
		return executeFTPBanner(ctx, req)
	case "ftp-feat":
		return executeFTPFEAT(ctx, req)
	case "ftp-auth-tls":
		return executeFTPAuthTLS(ctx, req)
	default:
		return AppResult{}, fmt.Errorf("unsupported ftp method %q", req.Method)
	}
}

func executeFTPBanner(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, _, banner, err := openFTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	product, version := parseFTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":        banner.Line,
		"response_code": banner.Code,
		"product":       product,
		"version":       version,
	}
	extra := map[string]any{
		"banner": banner.Line,
	}

	return AppResult{
		RawStatus:       strconv.Itoa(banner.Code),
		RequestSummary:  "connect read-banner",
		ResponseSummary: banner.Line,
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeFTPFEAT(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, tp, banner, err := openFTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	reply, features, err := ftpFEAT(tp)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "FEAT",
			ErrorText:      err.Error(),
		}, nil
	}

	product, version := parseFTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":              banner.Line,
		"response_code":       reply.Code,
		"feat_ok":             reply.Code == 211,
		"features":            features,
		"auth_tls_advertised": containsFTPFeature(features, "AUTH TLS"),
		"product":             product,
		"version":             version,
	}
	extra := map[string]any{
		"banner":        banner.Line,
		"feat_response": reply.Lines,
		"features":      features,
	}

	return AppResult{
		RawStatus:      strconv.Itoa(reply.Code),
		RequestSummary: "FEAT",
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("features", previewText(strings.Join(features, ","), 120)),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func executeFTPAuthTLS(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, tp, banner, err := openFTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	featReply, features, err := ftpFEAT(tp)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "FEAT",
			ErrorText:      err.Error(),
		}, nil
	}

	product, version := parseFTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":              banner.Line,
		"response_code":       featReply.Code,
		"feat_ok":             featReply.Code == 211,
		"features":            features,
		"auth_tls_advertised": containsFTPFeature(features, "AUTH TLS"),
		"product":             product,
		"version":             version,
	}
	extra := map[string]any{
		"banner":        banner.Line,
		"feat_response": featReply.Lines,
		"features":      features,
	}
	if !containsFTPFeature(features, "AUTH TLS") {
		fields["auth_tls_ok"] = false
		return AppResult{
			RawStatus:       strconv.Itoa(featReply.Code),
			RequestSummary:  "FEAT",
			ResponseSummary: "auth_tls_advertised=false",
			Fields:          fields,
			Extra:           extra,
		}, nil
	}

	start := time.Now()
	if err := tp.PrintfLine("AUTH TLS"); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "AUTH TLS",
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}
	authReply, err := readFTPReply(tp)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "AUTH TLS",
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}
	fields["response_code"] = authReply.Code
	extra["auth_tls_response"] = authReply.Lines
	if authReply.Code != 234 {
		fields["auth_tls_ok"] = false
		return AppResult{
			RawStatus:       strconv.Itoa(authReply.Code),
			RequestSummary:  "AUTH TLS",
			ResponseSummary: authReply.Line,
			Fields:          fields,
			Extra:           extra,
		}, nil
	}

	serverName := strings.TrimSpace(req.SNI)
	if serverName == "" {
		serverName = strings.TrimSpace(req.Host)
	}
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: req.InsecureTLS,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(req.Timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		fields["auth_tls_ok"] = false
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "AUTH TLS",
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}

	state := tlsConn.ConnectionState()
	fields["auth_tls_ok"] = true
	fields["tls_version"] = tlsVersionString(state.Version)
	fields["tls_alpn"] = state.NegotiatedProtocol
	extra["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	extra["tls_version"] = tlsVersionString(state.Version)

	var subject, issuer string
	var sans []string
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		sans = append([]string(nil), cert.DNSNames...)
		fields["tls_subject"] = subject
		fields["tls_issuer"] = issuer
		if len(sans) > 0 {
			fields["tls_san"] = sans
		}
		extra["certificate"] = map[string]any{
			"subject": subject,
			"issuer":  issuer,
			"dns":     sans,
		}
	}

	return AppResult{
		RawStatus:      "success",
		RequestSummary: "AUTH TLS",
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("subject", subject),
			summaryPart("issuer", issuer),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func openFTPConn(ctx context.Context, req AppRequest) (net.Conn, *textproto.Conn, ftpReply, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, ftpReply{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tp := textproto.NewConn(conn)
	reply, err := readFTPReply(tp)
	if err != nil {
		conn.Close()
		return nil, nil, ftpReply{}, err
	}
	return conn, tp, reply, nil
}

func ftpFEAT(tp *textproto.Conn) (ftpReply, []string, error) {
	if err := tp.PrintfLine("FEAT"); err != nil {
		return ftpReply{}, nil, err
	}
	reply, err := readFTPReply(tp)
	if err != nil {
		return ftpReply{}, nil, err
	}
	return reply, normalizeFTPFeatures(reply.Lines), nil
}

func readFTPReply(tp *textproto.Conn) (ftpReply, error) {
	line, err := tp.ReadLine()
	if err != nil {
		return ftpReply{}, err
	}
	if len(line) < 3 {
		return ftpReply{}, fmt.Errorf("ftp reply too short")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return ftpReply{}, err
	}
	codeText := line[:3]
	lines := []string{ftpReplyLineContent(line, codeText)}
	if len(line) >= 4 && line[3] == '-' {
		for {
			line, err = tp.ReadLine()
			if err != nil {
				return ftpReply{}, err
			}
			lines = append(lines, ftpReplyLineContent(line, codeText))
			if strings.HasPrefix(line, codeText+" ") {
				break
			}
		}
	}
	return ftpReply{
		Code:  code,
		Line:  strings.TrimSpace(strings.Join(lines, " ")),
		Lines: trimNonEmptyLines(lines),
	}, nil
}

func ftpReplyLineContent(line string, codeText string) string {
	line = strings.TrimSpace(line)
	if len(line) >= 4 && strings.HasPrefix(line, codeText) && (line[3] == '-' || line[3] == ' ') {
		return strings.TrimSpace(line[4:])
	}
	return strings.TrimSpace(line)
}

func trimNonEmptyLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func normalizeFTPFeatures(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		canonical := strings.ToUpper(strings.TrimSuffix(line, ":"))
		switch canonical {
		case "FEATURES", "END", "END.":
			continue
		}
		if strings.HasPrefix(canonical, "FEATURES SUPPORTED") || strings.HasPrefix(canonical, "EXTENSIONS SUPPORTED") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func containsFTPFeature(features []string, want string) bool {
	want = strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(want)), " "))
	for _, feature := range features {
		normalized := strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(feature)), " "))
		if normalized == want {
			return true
		}
	}
	return false
}

func parseFTPBannerProductVersion(banner string) (string, string) {
	line := leadingBannerCodePattern.ReplaceAllString(strings.TrimSpace(firstLine(banner)), "")
	line = strings.Trim(line, " -")
	if line == "" {
		return "", ""
	}

	fields := strings.Fields(line)
	if len(fields) >= 3 && strings.EqualFold(fields[0], "FileZilla") && strings.EqualFold(fields[1], "Server") {
		version := ""
		if versionTokenPattern.MatchString(strings.Trim(fields[2], "[]()")) {
			version = strings.Trim(fields[2], "[]()")
		}
		return "FileZilla Server", version
	}
	return parseBannerProductVersion(line)
}
