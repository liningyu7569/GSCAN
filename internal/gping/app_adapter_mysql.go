package gping

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	mysqlClientLongPassword     uint32 = 0x00000001
	mysqlClientConnectWithDB    uint32 = 0x00000008
	mysqlClientProtocol41       uint32 = 0x00000200
	mysqlClientSSL              uint32 = 0x00000800
	mysqlClientTransactions     uint32 = 0x00002000
	mysqlClientSecureConnection uint32 = 0x00008000
	mysqlClientMultiStatements  uint32 = 0x00010000
	mysqlClientMultiResults     uint32 = 0x00020000
	mysqlClientPluginAuth       uint32 = 0x00080000
	mysqlClientConnectAttrs     uint32 = 0x00100000
	mysqlClientSessionTrack     uint32 = 0x00800000
	mysqlClientDeprecateEOF     uint32 = 0x01000000
)

type mysqlAdapter struct{}

type mysqlGreeting struct {
	ProtocolVersion  int
	ServerVersion    string
	ConnectionID     uint32
	CapabilityFlags  uint32
	CharacterSet     byte
	AuthPlugin       string
	SSLSupported     bool
	PluginAuth       bool
	CapabilityNames  []string
	ServerFlavorHint string
	Product          string
	Version          string
}

func (mysqlAdapter) Name() string { return "mysql" }

func (mysqlAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportsTLS:      true,
		SupportedMethods: []string{"mysql-greeting", "mysql-capabilities", "mysql-starttls"},
	}
}

func (mysqlAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	switch normalizeMethod(req.Method) {
	case "mysql-greeting":
		return executeMySQLGreeting(ctx, req)
	case "mysql-capabilities":
		return executeMySQLCapabilities(ctx, req)
	case "mysql-starttls":
		return executeMySQLStartTLS(ctx, req)
	default:
		return AppResult{}, fmt.Errorf("unsupported mysql method %q", req.Method)
	}
}

func executeMySQLGreeting(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, greeting, rtt, err := openMySQLGreeting(ctx, req)
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-greeting",
			ErrorText:      err.Error(),
		}, nil
	}

	fields, extra := mysqlGreetingFields(greeting)
	summary := strings.TrimSpace(strings.Join([]string{
		summaryPart("protocol", strconv.Itoa(greeting.ProtocolVersion)),
		summaryPart("version", greeting.ServerVersion),
		summaryPart("auth_plugin", greeting.AuthPlugin),
	}, " "))

	return AppResult{
		RawStatus:       "success",
		RequestSummary:  "connect read-greeting",
		ResponseSummary: summary,
		RTTMs:           rtt,
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeMySQLCapabilities(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, greeting, rtt, err := openMySQLGreeting(ctx, req)
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-capabilities",
			ErrorText:      err.Error(),
		}, nil
	}

	fields, extra := mysqlGreetingFields(greeting)
	summary := strings.TrimSpace(strings.Join([]string{
		summaryPart("ssl", fmt.Sprintf("%t", greeting.SSLSupported)),
		summaryPart("plugin_auth", fmt.Sprintf("%t", greeting.PluginAuth)),
		summaryPart("auth_plugin", greeting.AuthPlugin),
	}, " "))

	return AppResult{
		RawStatus:       "success",
		RequestSummary:  "connect read-capabilities",
		ResponseSummary: summary,
		RTTMs:           rtt,
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeMySQLStartTLS(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, greeting, _, err := openMySQLGreeting(ctx, req)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-greeting",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	fields, extra := mysqlGreetingFields(greeting)
	requestSummary := "connect read-greeting starttls"
	if !greeting.SSLSupported {
		fields["ssl_handshake_ok"] = false
		extra["ssl_supported"] = false
		return AppResult{
			RawStatus:       "success",
			RequestSummary:  requestSummary,
			ResponseSummary: "ssl_supported=false",
			Fields:          fields,
			Extra:           extra,
		}, nil
	}

	start := time.Now()
	if err := sendMySQLSSLRequest(conn, greeting); err != nil {
		fields["ssl_handshake_ok"] = false
		return AppResult{
			RawStatus:      "error",
			RequestSummary: requestSummary,
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}

	serverName := stringValue(req.SNI, req.Host)
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
		fields["ssl_handshake_ok"] = false
		return AppResult{
			RawStatus:      "error",
			RequestSummary: requestSummary,
			ErrorText:      err.Error(),
			Fields:         fields,
			Extra:          extra,
		}, nil
	}

	state := tlsConn.ConnectionState()
	fields["ssl_handshake_ok"] = true
	fields["tls_version"] = tlsVersionString(state.Version)
	fields["tls_alpn"] = state.NegotiatedProtocol
	extra["tls_version"] = tlsVersionString(state.Version)
	extra["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	extra["alpn"] = state.NegotiatedProtocol

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
		RequestSummary: requestSummary,
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("subject", subject),
			summaryPart("issuer", issuer),
			summaryPart("version", tlsVersionString(state.Version)),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func openMySQLGreeting(ctx context.Context, req AppRequest) (net.Conn, mysqlGreeting, *float64, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, mysqlGreeting{}, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, payload, err := readMySQLPacket(conn)
	if err != nil {
		return conn, mysqlGreeting{}, floatPtrValue(time.Since(start).Seconds() * 1000), err
	}
	greeting, err := parseMySQLGreeting(payload)
	return conn, greeting, floatPtrValue(time.Since(start).Seconds() * 1000), err
}

func readMySQLPacket(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return header[3], payload, nil
}

func parseMySQLGreeting(payload []byte) (mysqlGreeting, error) {
	if len(payload) < 5 {
		return mysqlGreeting{}, fmt.Errorf("mysql greeting too short")
	}
	greeting := mysqlGreeting{
		ProtocolVersion: int(payload[0]),
	}
	if greeting.ProtocolVersion <= 0 {
		return mysqlGreeting{}, fmt.Errorf("invalid mysql protocol version")
	}

	pos := 1
	versionEnd := bytesIndex(payload[pos:], 0x00)
	if versionEnd < 0 {
		return mysqlGreeting{}, fmt.Errorf("mysql greeting missing version string")
	}
	greeting.ServerVersion = string(payload[pos : pos+versionEnd])
	greeting.Version = greeting.ServerVersion
	pos += versionEnd + 1

	if len(payload) < pos+4+8+1+2 {
		return mysqlGreeting{}, fmt.Errorf("mysql greeting missing capability section")
	}
	greeting.ConnectionID = binary.LittleEndian.Uint32(payload[pos : pos+4])
	pos += 4
	pos += 8 // auth-plugin-data-part-1
	pos++    // filler

	lowerCaps := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2

	if len(payload) > pos {
		greeting.CharacterSet = payload[pos]
		pos++
	}
	if len(payload) < pos+2+2+1+10 {
		greeting.CapabilityFlags = uint32(lowerCaps)
	} else {
		pos += 2 // status flags
		upperCaps := binary.LittleEndian.Uint16(payload[pos : pos+2])
		pos += 2
		authPluginLen := int(payload[pos])
		pos++
		pos += 10 // reserved
		greeting.CapabilityFlags = uint32(lowerCaps) | uint32(upperCaps)<<16

		if greeting.CapabilityFlags&mysqlClientSecureConnection != 0 {
			authDataLen := authPluginLen - 8
			if authDataLen < 13 {
				authDataLen = 13
			}
			if authDataLen > 0 && pos < len(payload) {
				consume := authDataLen
				if pos+consume > len(payload) {
					consume = len(payload) - pos
				}
				pos += consume
			}
		}
		for pos < len(payload) && payload[pos] == 0x00 {
			pos++
		}
		if greeting.CapabilityFlags&mysqlClientPluginAuth != 0 && pos < len(payload) {
			pluginEnd := bytesIndex(payload[pos:], 0x00)
			if pluginEnd < 0 {
				greeting.AuthPlugin = strings.TrimSpace(string(payload[pos:]))
			} else {
				greeting.AuthPlugin = strings.TrimSpace(string(payload[pos : pos+pluginEnd]))
			}
		}
	}

	greeting.SSLSupported = greeting.CapabilityFlags&mysqlClientSSL != 0
	greeting.PluginAuth = greeting.CapabilityFlags&mysqlClientPluginAuth != 0
	greeting.CapabilityNames = mysqlCapabilityNames(greeting.CapabilityFlags)
	greeting.ServerFlavorHint, greeting.Product = mysqlFlavorHint(greeting.ServerVersion)
	return greeting, nil
}

func mysqlGreetingFields(greeting mysqlGreeting) (map[string]any, map[string]any) {
	fields := map[string]any{
		"protocol_version":   greeting.ProtocolVersion,
		"server_version":     greeting.ServerVersion,
		"version":            greeting.ServerVersion,
		"banner":             greeting.ServerVersion,
		"auth_plugin":        greeting.AuthPlugin,
		"ssl_supported":      greeting.SSLSupported,
		"plugin_auth":        greeting.PluginAuth,
		"capabilities":       greeting.CapabilityNames,
		"server_flavor_hint": greeting.ServerFlavorHint,
	}
	if greeting.Product != "" {
		fields["product"] = greeting.Product
	}
	extra := map[string]any{
		"protocol_version": greeting.ProtocolVersion,
		"server_version":   greeting.ServerVersion,
		"connection_id":    greeting.ConnectionID,
		"auth_plugin":      greeting.AuthPlugin,
		"capabilities":     greeting.CapabilityNames,
		"ssl_supported":    greeting.SSLSupported,
		"plugin_auth":      greeting.PluginAuth,
	}
	if greeting.ServerFlavorHint != "" {
		extra["server_flavor_hint"] = greeting.ServerFlavorHint
	}
	if greeting.Product != "" {
		extra["product_hint"] = greeting.Product
	}
	return fields, extra
}

func sendMySQLSSLRequest(conn net.Conn, greeting mysqlGreeting) error {
	flags := mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth | mysqlClientSSL
	flags &= greeting.CapabilityFlags | mysqlClientProtocol41 | mysqlClientSSL

	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], flags)
	binary.LittleEndian.PutUint32(payload[4:8], 1<<24)
	payload[8] = greeting.CharacterSet

	return writeMySQLPacket(conn, 1, payload)
}

func writeMySQLPacket(conn net.Conn, sequence byte, payload []byte) error {
	header := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		sequence,
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func mysqlCapabilityNames(flags uint32) []string {
	type capability struct {
		flag uint32
		name string
	}
	all := []capability{
		{mysqlClientLongPassword, "CLIENT_LONG_PASSWORD"},
		{mysqlClientConnectWithDB, "CLIENT_CONNECT_WITH_DB"},
		{mysqlClientProtocol41, "CLIENT_PROTOCOL_41"},
		{mysqlClientSSL, "CLIENT_SSL"},
		{mysqlClientTransactions, "CLIENT_TRANSACTIONS"},
		{mysqlClientSecureConnection, "CLIENT_SECURE_CONNECTION"},
		{mysqlClientMultiStatements, "CLIENT_MULTI_STATEMENTS"},
		{mysqlClientMultiResults, "CLIENT_MULTI_RESULTS"},
		{mysqlClientPluginAuth, "CLIENT_PLUGIN_AUTH"},
		{mysqlClientConnectAttrs, "CLIENT_CONNECT_ATTRS"},
		{mysqlClientSessionTrack, "CLIENT_SESSION_TRACK"},
		{mysqlClientDeprecateEOF, "CLIENT_DEPRECATE_EOF"},
	}
	out := make([]string, 0, len(all))
	for _, item := range all {
		if flags&item.flag != 0 {
			out = append(out, item.name)
		}
	}
	return out
}

func mysqlFlavorHint(version string) (string, string) {
	lower := strings.ToLower(strings.TrimSpace(version))
	switch {
	case strings.Contains(lower, "mariadb"):
		return "mariadb_like", "mariadb"
	case strings.Contains(lower, "percona"):
		return "percona_like", "percona"
	case lower != "":
		return "mysql_like", ""
	default:
		return "", ""
	}
}

func bytesIndex(value []byte, needle byte) int {
	for index, item := range value {
		if item == needle {
			return index
		}
	}
	return -1
}
