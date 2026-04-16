package gping

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type AppRequest struct {
	TargetIP string
	Port     int
	Protocol string

	Adapter string
	Method  string

	Host string
	SNI  string
	URL  string

	Headers map[string]string
	Body    []byte
	Params  map[string]any

	Timeout     time.Duration
	InsecureTLS bool
}

type AppResult struct {
	RawStatus       string
	RequestSummary  string
	ResponseSummary string
	RTTMs           *float64
	ErrorText       string
	Fields          map[string]any
	Extra           map[string]any
}

type AdapterCapabilities struct {
	SupportsTLS      bool
	SupportsHost     bool
	SupportsSNI      bool
	SupportsHeaders  bool
	SupportedMethods []string
}

type AppAdapter interface {
	Name() string
	Capabilities() AdapterCapabilities
	Execute(ctx context.Context, req AppRequest) (AppResult, error)
}

var appAdapters = map[string]AppAdapter{
	"http":  httpAdapter{},
	"dns":   dnsAdapter{},
	"ftp":   ftpAdapter{},
	"smtp":  smtpAdapter{},
	"redis": redisAdapter{},
	"ssh":   sshAdapter{},
	"mysql": mysqlAdapter{},
}

func adapterForAction(action ActionUnit) (AppAdapter, error) {
	adapterName := normalizeAdapter(action.Adapter)
	if adapterName == "" {
		adapterName = inferAdapterForMethod(action.Method)
	}
	if adapterName == "" {
		return nil, fmt.Errorf("app method %q is missing adapter information", action.Method)
	}
	adapter, ok := appAdapters[adapterName]
	if !ok {
		return nil, fmt.Errorf("unsupported gping app adapter %q", adapterName)
	}
	return adapter, nil
}

func buildAppRequest(target TargetContext, action ActionUnit) AppRequest {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	body := []byte(nil)
	if action.Body != "" {
		body = []byte(action.Body)
	}
	req := AppRequest{
		TargetIP:    target.IP,
		Port:        target.Port,
		Protocol:    target.Protocol,
		Adapter:     normalizeAdapter(action.Adapter),
		Method:      normalizeMethod(action.Method),
		Host:        stringValue(action.HostHeader, target.HostHeader),
		SNI:         stringValue(action.SNI, target.SNI),
		URL:         action.URL,
		Headers:     cloneHeaders(action.Headers),
		Body:        body,
		Params:      cloneAnyMap(action.Params),
		Timeout:     timeout,
		InsecureTLS: action.InsecureSkipVerify,
	}
	if req.Adapter == "" {
		req.Adapter = inferAdapterForMethod(action.Method)
	}
	if req.URL == "" && req.Adapter == "http" {
		req.URL = buildActionURL(target, action.Path)
	}
	if req.Host == "" {
		req.Host = target.HostHeader
	}
	if req.SNI == "" && req.Host != "" && !strings.EqualFold(req.Host, target.IP) {
		req.SNI = req.Host
	}
	return req
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
