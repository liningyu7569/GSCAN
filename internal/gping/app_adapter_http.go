package gping

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// httpAdapter HTTP/HTTPS 协议适配器，支持 HEAD/GET/POST 请求
type httpAdapter struct{}

// Name 返回适配器名称
func (httpAdapter) Name() string { return "http" }

// Capabilities 返回 HTTP 适配器支持的能力
func (httpAdapter) Capabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportsTLS:      true,
		SupportsHost:     true,
		SupportsSNI:      true,
		SupportsHeaders:  true,
		SupportedMethods: []string{"http-head", "http-get", "http-post"},
	}
}

// Execute 执行 HTTP 请求并返回结构化结果
func (httpAdapter) Execute(ctx context.Context, req AppRequest) (AppResult, error) {
	requestURL := strings.TrimSpace(req.URL)
	if requestURL == "" {
		return AppResult{}, nil
	}
	if _, err := url.Parse(requestURL); err != nil {
		return AppResult{}, err
	}

	method := strings.ToUpper(strings.TrimPrefix(normalizeMethod(req.Method), "http-"))
	var requestBody io.Reader
	if method == http.MethodPost && len(req.Body) > 0 {
		requestBody = strings.NewReader(string(req.Body))
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
	if err != nil {
		return AppResult{}, err
	}
	if req.Host != "" {
		request.Host = req.Host
		request.Header.Set("Host", req.Host)
	}
	if method == http.MethodPost && len(req.Body) > 0 && request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	for key, value := range req.Headers {
		request.Header.Set(key, value)
	}

	dialer := &net.Dialer{Timeout: req.Timeout}
	forcedAddress := net.JoinHostPort(req.TargetIP, strconv.Itoa(req.Port))
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: req.InsecureTLS,
			ServerName:         req.SNI,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, forcedAddress)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   req.Timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return AppResult{
			RawStatus:      "error",
			RequestSummary: summarizeHTTPRequest(request, string(req.Body), req.Host),
			ErrorText:      err.Error(),
		}, nil
	}
	defer response.Body.Close()

	preview := ""
	title := ""
	if request.Method != http.MethodHead {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		preview = strings.TrimSpace(string(body))
		if len(preview) > 512 {
			preview = preview[:512]
		}
		title = extractHTMLTitle(preview)
	}

	serverHeader := strings.TrimSpace(response.Header.Get("Server"))
	product, version := splitServerProduct(serverHeader)
	location := strings.TrimSpace(response.Header.Get("Location"))
	contentLength := response.Header.Get("Content-Length")
	rtt := time.Since(start).Seconds() * 1000

	summaryParts := []string{
		summaryPart("status", summarizeHTTPStatus(response.StatusCode)),
		summaryPart("server", serverHeader),
		summaryPart("location", location),
		summaryPart("title", title),
		summaryPart("length", contentLength),
	}

	fields := map[string]any{
		"status_code":  response.StatusCode,
		"server":       serverHeader,
		"location":     location,
		"title":        title,
		"body_preview": preview,
		"product":      product,
		"version":      version,
	}
	extra := map[string]any{
		"status_code": response.StatusCode,
		"headers":     response.Header,
	}
	if preview != "" {
		extra["body_preview"] = preview
	}
	if title != "" {
		extra["title"] = title
	}

	return AppResult{
		RawStatus:       summarizeHTTPStatus(response.StatusCode),
		RequestSummary:  summarizeHTTPRequest(request, string(req.Body), req.Host),
		ResponseSummary: strings.TrimSpace(strings.Join(summaryParts, " ")),
		RTTMs:           floatPtrValue(rtt),
		Fields:          fields,
		Extra:           extra,
	}, nil
}

func summarizeHTTPRequest(request *http.Request, body string, hostHeader string) string {
	path := request.URL.RequestURI()
	if path == "" {
		path = request.URL.Path
	}
	parts := []string{
		fmt.Sprintf("%s %s", request.Method, path),
		fmt.Sprintf("host=%s", hostHeader),
	}
	if body != "" {
		parts = append(parts, fmt.Sprintf("body=%dB", len(body)))
	}
	return strings.Join(parts, " ")
}
