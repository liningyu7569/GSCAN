package gping

func applyActionProtocol(target TargetContext, actions []ActionUnit) TargetContext {
	if len(actions) == 0 {
		return target
	}
	first := actions[0]
	inferred := protocolForAction(first)
	if inferred == "" {
		return target
	}
	target.Protocol = inferred
	if inferred == "icmp" {
		target.Port = 0
		target.Scheme = ""
		target.URL = ""
	}
	if target.Protocol == "tcp" && target.Scheme == "" && target.Port > 0 {
		target.Scheme = inferScheme(target.Port, target.SNI)
	}
	if target.Protocol == "udp" {
		target.Scheme = ""
		target.URL = ""
	}
	return target
}

func protocolForAction(action ActionUnit) string {
	if normalizeMethod(action.Method) == "dns-query" {
		if transport := normalizeProtocol(stringAny(action.Params["transport"])); transport != "" {
			return transport
		}
		return "udp"
	}
	return protocolForMethod(action.Method)
}

func protocolForMethod(method string) string {
	switch normalizeMethod(method) {
	case "icmp-echo-raw", "icmp-raw":
		return "icmp"
	case "tcp-syn", "tcp-raw", "tcp-connect", "banner-read", "tls-handshake",
		"http-head", "http-get", "http-post",
		"ftp-banner", "ftp-feat", "ftp-auth-tls",
		"smtp-banner", "smtp-ehlo", "smtp-starttls",
		"redis-ping", "redis-info-server", "redis-info-replication",
		"ssh-banner", "ssh-kexinit", "ssh-hostkey",
		"mysql-greeting", "mysql-capabilities", "mysql-starttls":
		return "tcp"
	default:
		return ""
	}
}
