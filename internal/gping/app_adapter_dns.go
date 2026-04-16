package gping

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

type dnsAdapter struct{}

func (dnsAdapter) Name() string { return "dns" }

func (dnsAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportedMethods: []string{"dns-query"},
	}
}

func (dnsAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	if normalizeMethod(req.Method) != "dns-query" {
		return AppResult{}, fmt.Errorf("unsupported dns method %q", req.Method)
	}
	return executeDNSQuery(ctx, req)
}

func executeDNSQuery(ctx context.Context, req AppRequest) (AppResult, error) {
	qname := stringValue(stringAny(req.Params["qname"]), "example.com")
	qtypeName := strings.ToUpper(stringValue(stringAny(req.Params["qtype"]), "A"))
	qtype, ok := dnsQTypes[qtypeName]
	if !ok {
		return AppResult{}, fmt.Errorf("unsupported dns qtype %q", qtypeName)
	}
	transport := strings.ToLower(strings.TrimSpace(stringValue(stringAny(req.Params["transport"]), req.Protocol)))
	if transport == "" || transport == "tcp" && req.Protocol == "udp" {
		transport = strings.ToLower(strings.TrimSpace(req.Protocol))
	}
	if transport == "" || transport == "tcp" && req.Port == 53 && req.Protocol == "" {
		transport = "udp"
	}
	if transport == "" {
		transport = "udp"
	}
	rd := boolAnyDefault(req.Params["rd"], true)

	queryID, packet, err := buildDNSQueryPacket(qname, qtype, rd)
	if err != nil {
		return AppResult{}, err
	}

	start := time.Now()
	response, err := dnsExchange(ctx, req, transport, packet)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: fmt.Sprintf("%s %s rd=%d transport=%s", qtypeName, qname, boolToInt(rd), transport),
			ErrorText:      err.Error(),
		}, nil
	}
	parsed, err := parseDNSResponse(response, queryID)
	if err != nil {
		return AppResult{
			RawStatus:      "malformed",
			RequestSummary: fmt.Sprintf("%s %s rd=%d transport=%s", qtypeName, qname, boolToInt(rd), transport),
			ErrorText:      err.Error(),
		}, nil
	}

	responseRole := "unknown"
	switch {
	case parsed.RA:
		responseRole = "resolver_like"
	case parsed.AA:
		responseRole = "authoritative_like"
	}

	fields := map[string]any{
		"qname":               qname,
		"qtype":               qtypeName,
		"transport":           transport,
		"rcode":               parsed.RCode,
		"answer_count":        parsed.AnswerCount,
		"authority_count":     parsed.AuthorityCount,
		"additional_count":    parsed.AdditionalCount,
		"aa":                  parsed.AA,
		"ra":                  parsed.RA,
		"truncated":           parsed.Truncated,
		"answers_preview":     parsed.AnswersPreview,
		"recursion_available": parsed.RA,
		"response_role":       responseRole,
	}
	extra := map[string]any{
		"qname":            qname,
		"qtype":            qtypeName,
		"transport":        transport,
		"rcode":            parsed.RCode,
		"answer_count":     parsed.AnswerCount,
		"authority_count":  parsed.AuthorityCount,
		"additional_count": parsed.AdditionalCount,
		"aa":               parsed.AA,
		"ra":               parsed.RA,
		"truncated":        parsed.Truncated,
		"answers":          parsed.AnswersPreview,
	}

	return AppResult{
		RawStatus:      parsed.RCode,
		RequestSummary: fmt.Sprintf("%s %s rd=%d transport=%s", qtypeName, qname, boolToInt(rd), transport),
		ResponseSummary: strings.TrimSpace(strings.Join([]string{
			summaryPart("rcode", parsed.RCode),
			summaryPart("answers", strconv.Itoa(parsed.AnswerCount)),
			summaryPart("aa", strconv.Itoa(boolToInt(parsed.AA))),
			summaryPart("ra", strconv.Itoa(boolToInt(parsed.RA))),
		}, " ")),
		RTTMs:  floatPtrValue(time.Since(start).Seconds() * 1000),
		Fields: fields,
		Extra:  extra,
	}, nil
}

var dnsQTypes = map[string]uint16{
	"A":     1,
	"NS":    2,
	"CNAME": 5,
	"TXT":   16,
	"AAAA":  28,
}

type dnsResponse struct {
	RCode           string
	AnswerCount     int
	AuthorityCount  int
	AdditionalCount int
	AA              bool
	RA              bool
	Truncated       bool
	AnswersPreview  []string
}

func buildDNSQueryPacket(qname string, qtype uint16, rd bool) (uint16, []byte, error) {
	if strings.TrimSpace(qname) == "" {
		return 0, nil, fmt.Errorf("dns qname cannot be empty")
	}
	id, err := randomUint16()
	if err != nil {
		return 0, nil, err
	}
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	flags := uint16(0)
	if rd {
		flags |= 1 << 8
	}
	binary.BigEndian.PutUint16(packet[2:4], flags)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, encodeDNSName(qname)...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1)
	packet = append(packet, q...)
	return id, packet, nil
}

func dnsExchange(ctx context.Context, req AppRequest, transport string, packet []byte) ([]byte, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	address := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))

	switch transport {
	case "tcp":
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(packet)))
		if _, err := conn.Write(append(lengthPrefix, packet...)); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, lengthPrefix); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(lengthPrefix))
		response := make([]byte, length)
		if _, err := io.ReadFull(conn, response); err != nil {
			return nil, err
		}
		return response, nil
	default:
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "udp", address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(packet); err != nil {
			return nil, err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

func parseDNSResponse(message []byte, queryID uint16) (dnsResponse, error) {
	if len(message) < 12 {
		return dnsResponse{}, fmt.Errorf("dns response too short")
	}
	id := binary.BigEndian.Uint16(message[0:2])
	if id != queryID {
		return dnsResponse{}, fmt.Errorf("dns response id mismatch")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	qdCount := int(binary.BigEndian.Uint16(message[4:6]))
	anCount := int(binary.BigEndian.Uint16(message[6:8]))
	nsCount := int(binary.BigEndian.Uint16(message[8:10]))
	arCount := int(binary.BigEndian.Uint16(message[10:12]))

	offset := 12
	for i := 0; i < qdCount; i++ {
		var err error
		offset, err = skipDNSName(message, offset)
		if err != nil {
			return dnsResponse{}, err
		}
		if offset+4 > len(message) {
			return dnsResponse{}, fmt.Errorf("dns question truncated")
		}
		offset += 4
	}

	answers := make([]string, 0, int(math.Min(float64(anCount), 4)))
	for i := 0; i < anCount; i++ {
		nameOffset, err := skipDNSName(message, offset)
		if err != nil {
			return dnsResponse{}, err
		}
		if nameOffset+10 > len(message) {
			return dnsResponse{}, fmt.Errorf("dns answer truncated")
		}
		rtype := binary.BigEndian.Uint16(message[nameOffset : nameOffset+2])
		rdLength := int(binary.BigEndian.Uint16(message[nameOffset+8 : nameOffset+10]))
		rdataStart := nameOffset + 10
		rdataEnd := rdataStart + rdLength
		if rdataEnd > len(message) {
			return dnsResponse{}, fmt.Errorf("dns rdata truncated")
		}
		if len(answers) < 4 {
			answers = append(answers, formatDNSAnswer(message, rtype, rdataStart, rdLength))
		}
		offset = rdataEnd
	}

	return dnsResponse{
		RCode:           dnsRCodeName(int(flags & 0x000f)),
		AnswerCount:     anCount,
		AuthorityCount:  nsCount,
		AdditionalCount: arCount,
		AA:              flags&(1<<10) != 0,
		RA:              flags&(1<<7) != 0,
		Truncated:       flags&(1<<9) != 0,
		AnswersPreview:  answers,
	}, nil
}

func encodeDNSName(name string) []byte {
	trimmed := strings.Trim(strings.TrimSpace(name), ".")
	if trimmed == "" {
		return []byte{0}
	}
	labels := strings.Split(trimmed, ".")
	out := make([]byte, 0, len(trimmed)+2)
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out
}

func skipDNSName(message []byte, offset int) (int, error) {
	for {
		if offset >= len(message) {
			return 0, fmt.Errorf("dns name truncated")
		}
		length := int(message[offset])
		switch {
		case length == 0:
			return offset + 1, nil
		case length&0xc0 == 0xc0:
			if offset+2 > len(message) {
				return 0, fmt.Errorf("dns compressed name truncated")
			}
			return offset + 2, nil
		default:
			offset++
			if offset+length > len(message) {
				return 0, fmt.Errorf("dns label truncated")
			}
			offset += length
		}
	}
}

func formatDNSAnswer(message []byte, rtype uint16, rdataStart int, rdLength int) string {
	switch rtype {
	case 1:
		if rdLength == 4 {
			return net.IP(message[rdataStart : rdataStart+4]).String()
		}
	case 28:
		if rdLength == 16 {
			return net.IP(message[rdataStart : rdataStart+16]).String()
		}
	case 5, 2:
		if value, err := readDNSName(message, rdataStart); err == nil {
			return value
		}
	case 16:
		if rdLength > 0 && rdataStart+1+int(message[rdataStart]) <= len(message) {
			size := int(message[rdataStart])
			return string(message[rdataStart+1 : rdataStart+1+size])
		}
	}
	return fmt.Sprintf("type=%d len=%d", rtype, rdLength)
}

func readDNSName(message []byte, offset int) (string, error) {
	labels := make([]string, 0, 4)
	seen := 0
	for {
		if offset >= len(message) {
			return "", fmt.Errorf("dns name truncated")
		}
		if seen > len(message) {
			return "", fmt.Errorf("dns name loop")
		}
		seen++
		length := int(message[offset])
		switch {
		case length == 0:
			return strings.Join(labels, "."), nil
		case length&0xc0 == 0xc0:
			if offset+1 >= len(message) {
				return "", fmt.Errorf("dns pointer truncated")
			}
			pointer := int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
			suffix, err := readDNSName(message, pointer)
			if err != nil {
				return "", err
			}
			if suffix != "" {
				labels = append(labels, suffix)
			}
			return strings.Join(labels, "."), nil
		default:
			offset++
			if offset+length > len(message) {
				return "", fmt.Errorf("dns label truncated")
			}
			labels = append(labels, string(message[offset:offset+length]))
			offset += length
		}
	}
}

func dnsRCodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", code)
	}
}

func randomUint16() (uint16, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

func boolAnyDefault(value any, fallback bool) bool {
	switch typed := value.(type) {
	case nil:
		return fallback
	case bool:
		return typed
	case string:
		text := strings.TrimSpace(strings.ToLower(typed))
		if text == "" {
			return fallback
		}
		return text == "true" || text == "1" || text == "yes"
	default:
		return fallback
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
