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

type smtpAdapter struct{}

func (smtpAdapter) Name() string { return "smtp" }

func (smtpAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportsTLS:      true,
		SupportedMethods: []string{"smtp-banner", "smtp-ehlo", "smtp-starttls"},
	}
}

func (smtpAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	switch normalizeMethod(req.Method) {
	case "smtp-banner":
		return executeSMTPBanner(ctx, req)
	case "smtp-ehlo":
		return executeSMTPEHLO(ctx, req)
	case "smtp-starttls":
		return executeSMTPStartTLS(ctx, req)
	default:
		return AppResult{}, fmt.Errorf("unsupported smtp method %q", req.Method)
	}
}

func executeSMTPBanner(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, tp, banner, err := openSMTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	product, version := parseSMTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":        banner.Line,
		"response_code": banner.Code,
		"product":       product,
		"version":       version,
	}
	extra := map[string]any{
		"banner": banner.Line,
	}

	_ = tp
	return AppResult{
		RawStatus:       strconv.Itoa(banner.Code),
		RequestSummary:  "connect read-banner",
		ResponseSummary: banner.Line,
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeSMTPEHLO(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, tp, banner, err := openSMTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	ehloName := stringValue(stringAny(req.Params["ehlo_name"]), "gping.local")
	start := time.Now()
	capabilities, code, lines, err := smtpEHLO(tp, ehloName)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "EHLO " + ehloName,
			ErrorText:      err.Error(),
		}, nil
	}

	product, version := parseSMTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":              banner.Line,
		"response_code":       code,
		"ehlo_ok":             code == 250,
		"capabilities":        capabilities,
		"starttls_advertised": containsStringInsensitive(capabilities, "STARTTLS"),
		"product":             product,
		"version":             version,
	}
	extra := map[string]any{
		"banner":        banner.Line,
		"capabilities":  capabilities,
		"ehlo_response": lines,
	}

	return AppResult{
		RawStatus:      strconv.Itoa(code),
		RequestSummary: "EHLO " + ehloName,
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("capabilities", previewText(strings.Join(capabilities, ","), 120)),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func executeSMTPStartTLS(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, tp, banner, err := openSMTPConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-banner",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	ehloName := stringValue(stringAny(req.Params["ehlo_name"]), "gping.local")
	capabilities, _, lines, err := smtpEHLO(tp, ehloName)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "EHLO " + ehloName,
			ErrorText:      err.Error(),
		}, nil
	}

	product, version := parseSMTPBannerProductVersion(banner.Line)
	fields := map[string]any{
		"banner":              banner.Line,
		"ehlo_ok":             true,
		"capabilities":        capabilities,
		"starttls_advertised": containsStringInsensitive(capabilities, "STARTTLS"),
		"product":             product,
		"version":             version,
	}
	extra := map[string]any{
		"banner":        banner.Line,
		"capabilities":  capabilities,
		"ehlo_response": lines,
	}
	if !containsStringInsensitive(capabilities, "STARTTLS") {
		fields["starttls_ok"] = false
		return AppResult{
			RawStatus:       "250",
			RequestSummary:  "EHLO " + ehloName,
			ResponseSummary: "starttls_advertised=false",
			Fields:          fields,
			Extra:           extra,
		}, nil
	}

	start := time.Now()
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "STARTTLS",
			ErrorText:      err.Error(),
		}, nil
	}
	startTLSReply, err := readSMTPReply(tp)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "STARTTLS",
			ErrorText:      err.Error(),
		}, nil
	}
	fields["response_code"] = startTLSReply.Code
	if startTLSReply.Code != 220 {
		fields["starttls_ok"] = false
		extra["starttls_response"] = startTLSReply.Lines
		return AppResult{
			RawStatus:       strconv.Itoa(startTLSReply.Code),
			RequestSummary:  "STARTTLS",
			ResponseSummary: startTLSReply.Line,
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
		fields["starttls_ok"] = false
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "STARTTLS",
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}

	state := tlsConn.ConnectionState()
	fields["starttls_ok"] = true
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
		RequestSummary: "STARTTLS",
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("subject", subject),
			summaryPart("issuer", issuer),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

type smtpReply struct {
	Code  int
	Line  string
	Lines []string
}

func openSMTPConn(ctx context.Context, req AppRequest) (net.Conn, *textproto.Conn, smtpReply, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, smtpReply{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tp := textproto.NewConn(conn)
	reply, err := readSMTPReply(tp)
	if err != nil {
		conn.Close()
		return nil, nil, smtpReply{}, err
	}
	return conn, tp, reply, nil
}

func smtpEHLO(tp *textproto.Conn, ehloName string) ([]string, int, []string, error) {
	if err := tp.PrintfLine("EHLO %s", ehloName); err != nil {
		return nil, 0, nil, err
	}
	reply, err := readSMTPReply(tp)
	if err != nil {
		return nil, 0, nil, err
	}
	capabilities := make([]string, 0, len(reply.Lines))
	for _, line := range reply.Lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, " ") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				capabilities = append(capabilities, fields[0])
				continue
			}
		}
		capabilities = append(capabilities, line)
	}
	return capabilities, reply.Code, reply.Lines, nil
}

func readSMTPReply(tp *textproto.Conn) (smtpReply, error) {
	line, err := tp.ReadLine()
	if err != nil {
		return smtpReply{}, err
	}
	if len(line) < 3 {
		return smtpReply{}, fmt.Errorf("smtp reply too short")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return smtpReply{}, err
	}
	lines := []string{strings.TrimSpace(line[4:])}
	for len(line) >= 4 && line[3] == '-' {
		line, err = tp.ReadLine()
		if err != nil {
			return smtpReply{}, err
		}
		if len(line) < 4 {
			return smtpReply{}, fmt.Errorf("smtp multiline reply malformed")
		}
		lines = append(lines, strings.TrimSpace(line[4:]))
	}
	return smtpReply{
		Code:  code,
		Line:  strings.TrimSpace(strings.Join(lines, " ")),
		Lines: lines,
	}, nil
}

func parseSMTPBannerProductVersion(banner string) (string, string) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "", ""
	}
	fields := strings.Fields(banner)
	for i := len(fields) - 1; i >= 0; i-- {
		token := strings.TrimSpace(fields[i])
		if token == "" {
			continue
		}
		if strings.Contains(token, "/") {
			return splitServerProduct(token)
		}
		if strings.Contains(token, "_") {
			parts := strings.SplitN(token, "_", 2)
			return strings.Trim(parts[0], "[]()"), strings.Trim(parts[1], "[]()")
		}
	}
	return "", ""
}
