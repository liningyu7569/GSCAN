package gping

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

func executeStack(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	switch normalizeMethod(action.Method) {
	case "tcp-connect":
		return executeTCPConnect(ctx, target, action)
	case "banner-read":
		return executeBannerRead(ctx, target, action)
	case "tls-handshake":
		return executeTLSHandshake(ctx, target, action)
	default:
		return routeEvidence{}, fmt.Errorf("unsupported stack method %q", action.Method)
	}
}

func executeTCPConnect(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		rtt := time.Since(start).Seconds() * 1000
		ev := routeEvidence{
			RTTMs:          floatPtrValue(rtt),
			RequestSummary: fmt.Sprintf("dial=tcp %s", address),
			ErrorText:      err.Error(),
		}
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused"):
			ev.RawStatus = "closed"
		case isTimeoutError(err):
			ev.RawStatus = "filtered"
		default:
			ev.RawStatus = "error"
		}
		return ev, nil
	}
	_ = conn.Close()

	rtt := time.Since(start).Seconds() * 1000
	return routeEvidence{
		RawStatus:       "open",
		RequestSummary:  fmt.Sprintf("dial=tcp %s", address),
		ResponseSummary: "tcp connection established",
		RTTMs:           floatPtrValue(rtt),
	}, nil
}

func executeTLSHandshake(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	address := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))
	serverName := stringValue(action.SNI, target.SNI)
	if serverName == "" && target.Host != target.IP {
		serverName = target.Host
	}

	dialer := net.Dialer{Timeout: timeout}

	start := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return routeEvidence{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("tls dial=%s sni=%s", address, serverName),
			ErrorText:      err.Error(),
		}, nil
	}
	defer rawConn.Close()

	client := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: action.InsecureSkipVerify,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = client.SetDeadline(deadline)
	} else {
		_ = client.SetDeadline(time.Now().Add(timeout))
	}

	if err := client.HandshakeContext(ctx); err != nil {
		rtt := time.Since(start).Seconds() * 1000
		return routeEvidence{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("tls-handshake=%s sni=%s", address, serverName),
			RTTMs:          floatPtrValue(rtt),
			ErrorText:      err.Error(),
		}, nil
	}

	state := client.ConnectionState()
	rtt := time.Since(start).Seconds() * 1000
	extra := map[string]any{
		"tls_version":  tlsVersionString(state.Version),
		"cipher_suite": tls.CipherSuiteName(state.CipherSuite),
		"alpn":         state.NegotiatedProtocol,
	}
	var (
		subject string
		issuer  string
		sans    []string
	)
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		sans = append([]string(nil), cert.DNSNames...)
		extra["certificate"] = map[string]any{
			"subject": subject,
			"issuer":  issuer,
			"dns":     sans,
		}
	}

	summary := strings.TrimSpace(strings.Join([]string{
		summaryPart("version", tlsVersionString(state.Version)),
		summaryPart("alpn", state.NegotiatedProtocol),
		summaryPart("subject", subject),
	}, " "))

	return routeEvidence{
		RawStatus:       "success",
		RequestSummary:  fmt.Sprintf("tls-handshake=%s sni=%s", address, serverName),
		ResponseSummary: summary,
		RTTMs:           floatPtrValue(rtt),
		Extra:           extra,
		TLSSubject:      subject,
		TLSIssuer:       issuer,
		TLSSANs:         sans,
		TLSALPN:         state.NegotiatedProtocol,
		TLSVersion:      tlsVersionString(state.Version),
	}, nil
}

func executeBannerRead(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	readBytes := action.ReadBytes
	if readBytes <= 0 {
		readBytes = 512
	}

	address := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		rtt := time.Since(start).Seconds() * 1000
		ev := routeEvidence{
			RTTMs:          floatPtrValue(rtt),
			RequestSummary: fmt.Sprintf("banner-read=%s bytes=%d", address, readBytes),
			ErrorText:      err.Error(),
		}
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused"):
			ev.RawStatus = "closed"
		case isTimeoutError(err):
			ev.RawStatus = "filtered"
		default:
			ev.RawStatus = "error"
		}
		return ev, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := decodeEscapedText(action.Payload)
	requestSummary := fmt.Sprintf("banner-read=%s bytes=%d", address, readBytes)
	if payload != "" {
		if _, err := conn.Write([]byte(payload)); err != nil {
			rtt := time.Since(start).Seconds() * 1000
			return routeEvidence{
				RawStatus:      "error",
				RequestSummary: requestSummary,
				RTTMs:          floatPtrValue(rtt),
				ErrorText:      err.Error(),
			}, nil
		}
		requestSummary = fmt.Sprintf("%s payload=%dB", requestSummary, len(payload))
	}

	buf := make([]byte, readBytes)
	n, err := conn.Read(buf)
	rtt := time.Since(start).Seconds() * 1000
	if err != nil && !errors.Is(err, io.EOF) && !isTimeoutError(err) {
		return routeEvidence{
			RawStatus:      "error",
			RequestSummary: requestSummary,
			RTTMs:          floatPtrValue(rtt),
			ErrorText:      err.Error(),
		}, nil
	}
	if n <= 0 {
		status := "open"
		if isTimeoutError(err) {
			status = "timeout"
		}
		return routeEvidence{
			RawStatus:      status,
			RequestSummary: requestSummary,
			RTTMs:          floatPtrValue(rtt),
			ResponseSummary: func() string {
				if status == "timeout" {
					return "connected but no banner received before timeout"
				}
				return "connected but no banner received"
			}(),
		}, nil
	}

	banner := string(buf[:n])
	product, version := parseBannerProductVersion(banner)
	extra := map[string]any{
		"banner_text":  banner,
		"banner_first": firstLine(banner),
		"read_bytes":   n,
	}

	summaryParts := []string{
		summaryPart("banner", previewText(firstLine(banner), 80)),
		summaryPart("product", product),
		summaryPart("version", version),
	}

	return routeEvidence{
		RawStatus:       "banner",
		RequestSummary:  requestSummary,
		ResponseSummary: strings.TrimSpace(strings.Join(summaryParts, " ")),
		RTTMs:           floatPtrValue(rtt),
		Extra:           extra,
		Banner:          banner,
		Product:         product,
		Version:         version,
	}, nil
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func summaryPart(key string, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", key, strings.TrimSpace(value))
}
