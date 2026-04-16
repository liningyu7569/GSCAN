package gping

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	sshMessageKexInit      = 20
	sshMessageKexECDHInit  = 30
	sshMessageKexECDHReply = 31
)

type sshAdapter struct{}

type sshKexInit struct {
	KexAlgorithms         []string
	HostKeyAlgorithms     []string
	CiphersClientToServer []string
	CiphersServerToClient []string
	MACsClientToServer    []string
	MACsServerToClient    []string
}

func (sshAdapter) Name() string { return "ssh" }

func (sshAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportedMethods: []string{"ssh-banner", "ssh-kexinit", "ssh-hostkey"},
	}
}

func (sshAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	switch normalizeMethod(req.Method) {
	case "ssh-banner":
		return executeSSHBanner(ctx, req)
	case "ssh-kexinit":
		return executeSSHKexInit(ctx, req)
	case "ssh-hostkey":
		return executeSSHHostKey(ctx, req)
	default:
		return AppResult{}, fmt.Errorf("unsupported ssh method %q", req.Method)
	}
}

func executeSSHBanner(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, reader, err := openSSHConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-identification",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	banner, err := readSSHIdentification(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-identification",
			ErrorText:      err.Error(),
		}, nil
	}

	protocolVersion, softwareVersion, product, version := parseSSHBanner(banner)
	fields := map[string]any{
		"banner":           banner,
		"protocol_version": protocolVersion,
		"software_version": softwareVersion,
		"product":          product,
		"version":          version,
	}
	extra := map[string]any{
		"banner":           banner,
		"protocol_version": protocolVersion,
		"software_version": softwareVersion,
	}

	return AppResult{
		RawStatus:       "success",
		RequestSummary:  "connect read-identification",
		ResponseSummary: banner,
		RTTMs:           floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func executeSSHKexInit(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, reader, err := openSSHConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	banner, err := readSSHIdentification(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}
	if err := writeSSHIdentification(conn); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification",
			ErrorText:      err.Error(),
		}, nil
	}
	packet, err := readSSHPacket(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}
	kex, err := parseSSHKexInit(packet)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}

	protocolVersion, softwareVersion, product, version := parseSSHBanner(banner)
	fields := map[string]any{
		"banner":             banner,
		"protocol_version":   protocolVersion,
		"software_version":   softwareVersion,
		"product":            product,
		"version":            version,
		"kex_algorithms":     kex.KexAlgorithms,
		"hostkey_algorithms": kex.HostKeyAlgorithms,
		"ciphers":            kex.CiphersServerToClient,
		"macs":               kex.MACsServerToClient,
	}
	extra := map[string]any{
		"banner":                   banner,
		"kex_algorithms":           kex.KexAlgorithms,
		"hostkey_algorithms":       kex.HostKeyAlgorithms,
		"ciphers_client_to_server": kex.CiphersClientToServer,
		"ciphers_server_to_client": kex.CiphersServerToClient,
		"macs_client_to_server":    kex.MACsClientToServer,
		"macs_server_to_client":    kex.MACsServerToClient,
	}

	return AppResult{
		RawStatus:      "success",
		RequestSummary: "send-identification read-kexinit",
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("kex", previewText(strings.Join(kex.KexAlgorithms, ","), 80)),
			summaryPart("hostkey", previewText(strings.Join(kex.HostKeyAlgorithms, ","), 80)),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func executeSSHHostKey(ctx context.Context, req AppRequest) (AppResult, error) {
	conn, reader, err := openSSHConn(ctx, req)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-hostkey",
			ErrorText:      err.Error(),
		}, nil
	}
	defer conn.Close()

	start := time.Now()
	banner, err := readSSHIdentification(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "connect read-hostkey",
			ErrorText:      err.Error(),
		}, nil
	}
	if err := writeSSHIdentification(conn); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification",
			ErrorText:      err.Error(),
		}, nil
	}
	serverPacket, err := readSSHPacket(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}
	serverKex, err := parseSSHKexInit(serverPacket)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification read-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}
	if !containsStringInsensitive(serverKex.KexAlgorithms, "ecdh-sha2-nistp256") {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-identification read-kexinit",
			ErrorText:      "server kexinit does not advertise ecdh-sha2-nistp256",
		}, nil
	}

	if err := writeSSHPacket(conn, buildClientSSHKexInitPacket()); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-client-kexinit",
			ErrorText:      err.Error(),
		}, nil
	}

	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "generate-ecdh-key",
			ErrorText:      err.Error(),
		}, nil
	}
	clientPublic := privateKey.PublicKey().Bytes()
	if err := writeSSHPacket(conn, buildSSHECDHInitPacket(clientPublic)); err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-ecdh-init",
			ErrorText:      err.Error(),
		}, nil
	}

	replyPacket, err := readSSHPacket(reader)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-ecdh-init read-hostkey",
			ErrorText:      err.Error(),
		}, nil
	}
	hostKeyBlob, hostKeyType, fingerprint, err := parseSSHHostKeyReply(replyPacket)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: "send-ecdh-init read-hostkey",
			ErrorText:      err.Error(),
		}, nil
	}

	protocolVersion, softwareVersion, product, version := parseSSHBanner(banner)
	fields := map[string]any{
		"banner":              banner,
		"protocol_version":    protocolVersion,
		"software_version":    softwareVersion,
		"product":             product,
		"version":             version,
		"hostkey_type":        hostKeyType,
		"hostkey_fingerprint": fingerprint,
		"hostkey_algorithms":  serverKex.HostKeyAlgorithms,
	}
	extra := map[string]any{
		"banner":              banner,
		"hostkey_type":        hostKeyType,
		"hostkey_fingerprint": fingerprint,
		"hostkey_blob_size":   len(hostKeyBlob),
		"hostkey_algorithms":  serverKex.HostKeyAlgorithms,
	}

	return AppResult{
		RawStatus:      "success",
		RequestSummary: "send-identification send-client-kexinit send-ecdh-init",
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("hostkey", hostKeyType),
			summaryPart("fingerprint", fingerprint),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

func openSSHConn(ctx context.Context, req AppRequest) (net.Conn, *bufio.Reader, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, bufio.NewReader(conn), nil
}

func readSSHIdentification(reader *bufio.Reader) (string, error) {
	for attempts := 0; attempts < 5; attempts++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
	}
	return "", fmt.Errorf("ssh identification not found")
}

func writeSSHIdentification(conn net.Conn) error {
	_, err := io.WriteString(conn, "SSH-2.0-gping_0.1\r\n")
	return err
}

func parseSSHBanner(banner string) (string, string, string, string) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "", "", "", ""
	}
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return "", "", "", ""
	}
	protocolVersion := parts[1]
	softwareVersion := parts[2]
	if index := strings.Index(softwareVersion, " "); index >= 0 {
		softwareVersion = softwareVersion[:index]
	}
	product := softwareVersion
	version := ""
	if strings.Contains(softwareVersion, "_") {
		chunks := strings.SplitN(softwareVersion, "_", 2)
		product = chunks[0]
		version = chunks[1]
	}
	return protocolVersion, softwareVersion, product, version
}

func readSSHPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	packetLength := binary.BigEndian.Uint32(header[:4])
	paddingLength := int(header[4])
	if packetLength < uint32(paddingLength+1) {
		return nil, fmt.Errorf("invalid ssh packet length")
	}
	rest := make([]byte, packetLength-1)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return nil, err
	}
	if int(packetLength) < paddingLength+1 {
		return nil, fmt.Errorf("invalid ssh padding")
	}
	payload := rest[:len(rest)-paddingLength]
	return payload, nil
}

func writeSSHPacket(conn net.Conn, payload []byte) error {
	blockSize := 8
	paddingLength := blockSize - ((len(payload) + 5) % blockSize)
	if paddingLength < 4 {
		paddingLength += blockSize
	}
	packetLength := uint32(len(payload) + paddingLength + 1)
	padding := make([]byte, paddingLength)
	if _, err := rand.Read(padding); err != nil {
		return err
	}

	buf := make([]byte, 4+1+len(payload)+len(padding))
	binary.BigEndian.PutUint32(buf[:4], packetLength)
	buf[4] = byte(paddingLength)
	copy(buf[5:], payload)
	copy(buf[5+len(payload):], padding)
	_, err := conn.Write(buf)
	return err
}

func parseSSHKexInit(payload []byte) (sshKexInit, error) {
	if len(payload) < 17 || payload[0] != sshMessageKexInit {
		return sshKexInit{}, fmt.Errorf("ssh packet is not KEXINIT")
	}
	reader := &sshPayloadReader{data: payload[17:]}
	kexAlgorithms, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	hostKeyAlgorithms, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	ciphersClient, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	ciphersServer, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	macsClient, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	macsServer, err := reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	_, err = reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	_, err = reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	_, err = reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	_, err = reader.readNameList()
	if err != nil {
		return sshKexInit{}, err
	}
	return sshKexInit{
		KexAlgorithms:         kexAlgorithms,
		HostKeyAlgorithms:     hostKeyAlgorithms,
		CiphersClientToServer: ciphersClient,
		CiphersServerToClient: ciphersServer,
		MACsClientToServer:    macsClient,
		MACsServerToClient:    macsServer,
	}, nil
}

func buildClientSSHKexInitPacket() []byte {
	payload := make([]byte, 0, 512)
	payload = append(payload, sshMessageKexInit)
	payload = append(payload, make([]byte, 16)...)
	payload = appendSSHNameList(payload, []string{"ecdh-sha2-nistp256", "curve25519-sha256", "diffie-hellman-group14-sha1"})
	payload = appendSSHNameList(payload, []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"})
	payload = appendSSHNameList(payload, []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"})
	payload = appendSSHNameList(payload, []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"})
	payload = appendSSHNameList(payload, []string{"hmac-sha2-256", "hmac-sha1"})
	payload = appendSSHNameList(payload, []string{"hmac-sha2-256", "hmac-sha1"})
	payload = appendSSHNameList(payload, []string{"none", "zlib@openssh.com", "zlib"})
	payload = appendSSHNameList(payload, []string{"none", "zlib@openssh.com", "zlib"})
	payload = appendSSHNameList(payload, nil)
	payload = appendSSHNameList(payload, nil)
	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)
	return payload
}

func buildSSHECDHInitPacket(publicKey []byte) []byte {
	payload := []byte{sshMessageKexECDHInit}
	return appendSSHString(payload, publicKey)
}

func parseSSHHostKeyReply(payload []byte) ([]byte, string, string, error) {
	if len(payload) == 0 || payload[0] != sshMessageKexECDHReply {
		return nil, "", "", fmt.Errorf("ssh packet is not KEX_ECDH_REPLY")
	}
	reader := &sshPayloadReader{data: payload[1:]}
	hostKeyBlob, err := reader.readString()
	if err != nil {
		return nil, "", "", err
	}
	hostKeyType, err := sshHostKeyType(hostKeyBlob)
	if err != nil {
		return nil, "", "", err
	}
	fingerprint := sshHostKeyFingerprint(hostKeyBlob)
	return hostKeyBlob, hostKeyType, fingerprint, nil
}

func sshHostKeyType(blob []byte) (string, error) {
	reader := &sshPayloadReader{data: blob}
	value, err := reader.readString()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func sshHostKeyFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

type sshPayloadReader struct {
	data []byte
	pos  int
}

func (r *sshPayloadReader) readString() ([]byte, error) {
	if r.pos+4 > len(r.data) {
		return nil, fmt.Errorf("ssh payload truncated")
	}
	length := int(binary.BigEndian.Uint32(r.data[r.pos : r.pos+4]))
	r.pos += 4
	if r.pos+length > len(r.data) {
		return nil, fmt.Errorf("ssh string truncated")
	}
	value := r.data[r.pos : r.pos+length]
	r.pos += length
	return value, nil
}

func (r *sshPayloadReader) readNameList() ([]string, error) {
	value, err := r.readString()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(value))
	if text == "" {
		return nil, nil
	}
	parts := strings.Split(text, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out, nil
}

func appendSSHNameList(dst []byte, values []string) []byte {
	return appendSSHString(dst, []byte(strings.Join(values, ",")))
}

func appendSSHString(dst []byte, value []byte) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(value)))
	dst = append(dst, buf...)
	dst = append(dst, value...)
	return dst
}

func containsStringInsensitive(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}
