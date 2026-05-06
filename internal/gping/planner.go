package gping

import (
	"fmt"
	"sort"
	"strings"
)

// Plan 根据选项和目标规划动作列表：优先使用模板，否则按单次方法构建
func Plan(opts Options, target TargetContext) ([]ActionUnit, string, error) {
	if strings.TrimSpace(opts.TemplateName) != "" {
		spec, err := LoadTemplate(opts.TemplateName)
		if err != nil {
			return nil, "", err
		}
		return planFromTemplate(spec, opts, target)
	}

	route := normalizeRoute(opts.Route)
	method := normalizeMethod(opts.Method)
	if method == "" {
		return nil, "", fmt.Errorf("either --template or --method is required")
	}
	methodRoute, ok := supportedMethods()[method]
	if !ok {
		return nil, "", fmt.Errorf("unsupported gping method %q", method)
	}
	if route == "" {
		route = methodRoute
	}
	if route != methodRoute {
		return nil, "", fmt.Errorf("method %q must run on route %q", method, methodRoute)
	}

	action, err := buildSingleAction(route, method, opts, target)
	if err != nil {
		return nil, "", err
	}
	return []ActionUnit{action}, "", nil
}

// planFromTemplate 根据模板定义展开变量并构建动作列表
func planFromTemplate(spec TemplateSpec, opts Options, target TargetContext) ([]ActionUnit, string, error) {
	vars, err := buildTemplateVars(spec, opts, target)
	if err != nil {
		return nil, "", err
	}

	steps := spec.Steps()
	actions := make([]ActionUnit, 0, len(steps))
	seenIDs := make(map[string]int)
	for index, actionSpec := range steps {
		route := normalizeRoute(actionSpec.Route)
		method := normalizeMethod(actionSpec.Method)
		if method == "" || route == "" {
			return nil, "", fmt.Errorf("template %q action %d is missing route or method", spec.Name, index+1)
		}
		methodRoute, ok := supportedMethods()[method]
		if !ok {
			return nil, "", fmt.Errorf("template %q uses unsupported method %q", spec.Name, method)
		}
		if route != methodRoute {
			return nil, "", fmt.Errorf("template %q action %d uses mismatched route/method %s/%s", spec.Name, index+1, route, method)
		}

		adapter := normalizeAdapter(actionSpec.Adapter)
		if route == "app" && adapter == "" {
			adapter = inferAdapterForMethod(method)
		}

		actionParams := expandAnyMap(actionSpec.Params, vars)
		action := ActionUnit{
			Index:              index + 1,
			ID:                 uniqueStepID(actionSpec, index, seenIDs),
			Name:               expandString(actionSpec.Name, vars),
			Route:              route,
			Adapter:            adapter,
			Method:             method,
			URL:                expandString(actionSpec.URL, vars),
			HostHeader:         expandString(actionSpec.HostHeader, vars),
			SNI:                expandString(actionSpec.SNI, vars),
			Path:               expandString(actionSpec.Path, vars),
			Body:               decodeEscapedText(expandString(actionSpec.Body, vars)),
			Payload:            decodeEscapedText(expandString(actionSpec.Payload, vars)),
			ReadBytes:          actionSpec.ReadBytes,
			Headers:            expandMap(actionSpec.Headers, vars),
			Params:             actionParams,
			When:               expandString(actionSpec.When, vars),
			ContinueOnError:    actionSpec.ContinueOnError,
			InsecureSkipVerify: actionSpec.InsecureSkipVerify || opts.InsecureSkipVerify,
			Timeout:            opts.Timeout,
		}
		applyActionParams(&action)
		if action.URL == "" && actionUsesURL(action) {
			action.URL = buildActionURL(target, action.Path)
		}
		if action.HostHeader == "" {
			action.HostHeader = target.HostHeader
		}
		if action.SNI == "" {
			action.SNI = target.SNI
		}
		actions = append(actions, action)
	}
	return actions, spec.Name, nil
}

// buildSingleAction 为单次命令行调用构建单个探测动作
func buildSingleAction(route string, method string, opts Options, target TargetContext) (ActionUnit, error) {
	action := ActionUnit{
		Index:              1,
		ID:                 "step1",
		Route:              route,
		Adapter:            inferAdapterForMethod(method),
		Method:             method,
		HostHeader:         stringValue(opts.HostHeader, target.HostHeader),
		SNI:                stringValue(opts.SNI, target.SNI),
		Path:               stringValue(opts.Path, target.Path),
		Body:               decodeEscapedText(opts.Body),
		Payload:            decodeEscapedText(strings.TrimSpace(opts.Payload)),
		ReadBytes:          opts.ReadBytes,
		Headers:            cloneHeaders(opts.Headers),
		InsecureSkipVerify: opts.InsecureSkipVerify,
		Timeout:            opts.Timeout,
	}
	if route == "raw" {
		params, err := buildRawActionParams(opts, method)
		if err != nil {
			return ActionUnit{}, err
		}
		action.Params = params
	}
	if route == "app" && action.Adapter == "dns" {
		action.Params = map[string]any{
			"transport": stringValue(strings.TrimSpace(opts.Protocol), "udp"),
		}
	}
	if actionUsesURL(action) {
		action.URL = buildActionURL(target, action.Path)
	}
	if route == "raw" && method == "icmp-echo-raw" {
		action.Path = ""
	}
	return action, nil
}

func buildRawActionParams(opts Options, method string) (map[string]any, error) {
	params := make(map[string]any)
	addInt := func(key string, value int, min int, max int) error {
		if value < 0 {
			return nil
		}
		if value < min || value > max {
			return fmt.Errorf("%s must be in range %d-%d", key, min, max)
		}
		params[key] = value
		return nil
	}
	addInt64 := func(key string, value int64, min int64, max int64) error {
		if value < 0 {
			return nil
		}
		if value < min || value > max {
			return fmt.Errorf("%s must be in range %d-%d", key, min, max)
		}
		params[key] = value
		return nil
	}

	if opts.Retries < 0 {
		return nil, fmt.Errorf("retries must be >= 0")
	}
	if opts.Retries > 0 {
		params["retries"] = opts.Retries
	}
	if err := addInt("ttl", opts.TTL, 0, 255); err != nil {
		return nil, err
	}
	if err := addInt("tos", opts.TOS, 0, 255); err != nil {
		return nil, err
	}
	if err := addInt("ip_id", opts.IPID, 0, 65535); err != nil {
		return nil, err
	}
	if opts.DF {
		params["df"] = true
	}
	if opts.BadSum {
		params["bad_checksum"] = true
	}
	if strings.TrimSpace(opts.PayloadHex) != "" {
		params["payload_hex"] = strings.TrimSpace(opts.PayloadHex)
	}

	switch normalizeMethod(method) {
	case "tcp-syn", "tcp-raw":
		if err := addInt("src_port", opts.SourcePort, 1, 65535); err != nil {
			return nil, err
		}
		if err := addInt64("tcp_seq", opts.TCPSeq, 0, 4294967295); err != nil {
			return nil, err
		}
		if err := addInt64("tcp_ack", opts.TCPAck, 0, 4294967295); err != nil {
			return nil, err
		}
		if err := addInt("tcp_window", opts.TCPWindow, 0, 65535); err != nil {
			return nil, err
		}
		if flags := strings.TrimSpace(opts.TCPFlags); flags != "" {
			params["tcp_flags"] = flags
		}
	case "icmp-echo-raw", "icmp-raw":
		if err := addInt("icmp_id", opts.ICMPID, 0, 65535); err != nil {
			return nil, err
		}
		if err := addInt("icmp_seq", opts.ICMPSeq, 0, 65535); err != nil {
			return nil, err
		}
		if err := addInt("icmp_type", opts.ICMPType, 0, 255); err != nil {
			return nil, err
		}
		if err := addInt("icmp_code", opts.ICMPCode, 0, 255); err != nil {
			return nil, err
		}
	}

	if len(params) == 0 {
		return nil, nil
	}
	return params, nil
}

func buildTemplateVars(spec TemplateSpec, opts Options, target TargetContext) (map[string]string, error) {
	vars := baseTemplateVars(opts, target)
	keys := sortedTemplateVarKeys(spec.Vars)
	for _, key := range keys {
		value := spec.Vars[key]
		if vars[key] == "" && value.Default != "" {
			vars[key] = expandString(value.Default, vars)
		}
	}
	for _, key := range keys {
		value := spec.Vars[key]
		if vars[key] == "" && value.DefaultFrom != "" {
			vars[key] = strings.TrimSpace(vars[strings.TrimSpace(value.DefaultFrom)])
		}
	}
	for key, value := range opts.Vars {
		vars[key] = value
	}
	for _, key := range keys {
		value := spec.Vars[key]
		if value.Required && strings.TrimSpace(vars[key]) == "" {
			return nil, fmt.Errorf("template %q requires variable %q", spec.Name, key)
		}
	}
	return vars, nil
}

func baseTemplateVars(opts Options, target TargetContext) map[string]string {
	vars := make(map[string]string, len(opts.Vars)+12)
	vars["ip"] = target.IP
	vars["port"] = fmt.Sprintf("%d", target.Port)
	vars["protocol"] = target.Protocol
	vars["scheme"] = target.Scheme
	vars["host"] = stringValue(target.HostHeader, target.Host)
	vars["host_header"] = stringValue(target.HostHeader, target.Host)
	vars["sni"] = target.SNI
	vars["path"] = stringValue(opts.Path, target.Path)
	vars["current_service"] = target.CurrentService
	vars["current_product"] = target.CurrentProduct
	vars["current_version"] = target.CurrentVersion
	vars["current_banner"] = target.CurrentBanner
	if strings.TrimSpace(opts.HostHeader) != "" {
		vars["host"] = strings.TrimSpace(opts.HostHeader)
		vars["host_header"] = strings.TrimSpace(opts.HostHeader)
	}
	if strings.TrimSpace(opts.SNI) != "" {
		vars["sni"] = strings.TrimSpace(opts.SNI)
	}
	return vars
}

func expandString(value string, vars map[string]string) string {
	out := value
	for key, replacement := range vars {
		out = strings.ReplaceAll(out, "${"+key+"}", replacement)
	}
	return out
}

func expandMap(values map[string]string, vars map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[expandString(key, vars)] = expandString(value, vars)
	}
	return out
}

func expandAnyMap(values map[string]any, vars map[string]string) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[expandString(key, vars)] = expandAny(values[key], vars)
	}
	return out
}

func expandAny(value any, vars map[string]string) any {
	switch typed := value.(type) {
	case string:
		return expandString(typed, vars)
	case map[string]any:
		return expandAnyMap(typed, vars)
	case map[string]string:
		return expandMap(typed, vars)
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, expandAny(item, vars))
		}
		return out
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, expandString(item, vars))
		}
		return out
	default:
		return value
	}
}

func uniqueStepID(step TemplateActionSpec, index int, seen map[string]int) string {
	base := normalizeStepID(step.ID)
	if base == "" {
		base = normalizeStepID(step.Name)
	}
	if base == "" {
		base = normalizeStepID(step.Method)
	}
	if base == "" {
		base = fmt.Sprintf("step%d", index+1)
	}
	seen[base]++
	if seen[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s_%d", base, seen[base])
}

func normalizeStepID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "_", "-", "_", "/", "_", ".", "_")
	return replacer.Replace(value)
}

func buildActionURL(target TargetContext, path string) string {
	host := target.HostHeader
	if host == "" {
		host = target.Host
	}
	if host == "" {
		host = target.IP
	}
	scheme := target.Scheme
	if scheme == "" {
		scheme = inferScheme(target.Port, target.SNI)
	}
	return buildURLString(scheme, host, target.Port, path)
}
