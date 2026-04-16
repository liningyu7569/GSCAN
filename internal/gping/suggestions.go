package gping

import (
	"sort"
	"strings"
)

func SuggestTemplates(target TargetContext) []string {
	return suggestTemplateNames(
		target.Protocol,
		target.Port,
		target.Scheme,
		target.CurrentService,
		target.CurrentProduct,
		target.CurrentBanner,
	)
}

func SuggestTemplatesForCandidate(item Candidate) []string {
	return suggestTemplateNames(
		item.Protocol,
		item.Port,
		inferScheme(item.Port, ""),
		item.CurrentService,
		item.CurrentProduct,
		item.CurrentBanner,
	)
}

func suggestTemplateNames(protocol string, port int, scheme string, service string, product string, banner string) []string {
	target := TargetContext{
		Protocol:       protocol,
		Port:           port,
		Scheme:         scheme,
		CurrentService: service,
		CurrentProduct: product,
		CurrentBanner:  banner,
	}

	out := make([]string, 0, 4)
	seen := make(map[string]struct{})
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	if templates, err := loadBuiltinTemplates(); err == nil {
		names := make([]string, 0, len(templates))
		for name := range templates {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			spec := templates[name]
			if spec.AppliesTo.IsZero() {
				continue
			}
			if templateMatchesTarget(spec, target) {
				add(name)
			}
		}
	}

	protocol = normalizeProtocol(protocol)
	if protocol != "" && protocol != "tcp" && protocol != "udp" {
		return out
	}

	service = strings.ToLower(strings.TrimSpace(service))
	productText := strings.ToLower(strings.TrimSpace(strings.Join([]string{product, banner}, " ")))
	scheme = strings.ToLower(strings.TrimSpace(scheme))

	likelyHTTPS := scheme == "https" ||
		service == "https" ||
		port == 443 || port == 8443 ||
		strings.Contains(productText, "tls")

	likelyHTTP := likelyHTTPS ||
		scheme == "http" ||
		service == "http" ||
		port == 80 || port == 8080 || port == 8000

	bannerFriendly := service == "ftp" ||
		service == "smtp" ||
		service == "pop3" ||
		service == "imap" ||
		service == "ssh" ||
		service == "redis" ||
		service == "mysql" ||
		port == 21 || port == 22 || port == 25 || port == 110 || port == 143 ||
		port == 3306 || port == 6379

	proxyLike := strings.Contains(productText, "envoy") ||
		strings.Contains(productText, "openresty") ||
		strings.Contains(productText, "nginx") ||
		strings.Contains(productText, "haproxy") ||
		strings.Contains(productText, "traefik")

	if service == "dns" || port == 53 {
		add("dns/basic-confirm")
		add("uam/dns-enrich")
	}
	if protocol == "udp" {
		return out
	}
	if service == "ftp" || port == 21 {
		add("ftp/basic-confirm")
		add("uam/ftp-enrich")
	}
	if likelyHTTPS {
		add("uam/https-enrich")
	}
	if likelyHTTP || proxyLike {
		add("http/reverse-proxy-confirm")
	}
	if bannerFriendly {
		add("stack/basic-banner-read")
	}
	if service == "mysql" || port == 3306 {
		add("mysql/basic-confirm")
		add("uam/mysql-enrich")
	}
	if service == "smtp" || port == 25 || port == 587 || port == 465 {
		add("smtp/basic-confirm")
		add("uam/smtp-enrich")
	}
	if service == "redis" || port == 6379 {
		add("redis/basic-confirm")
		add("uam/redis-enrich")
	}
	if service == "ssh" || port == 22 {
		add("ssh/basic-confirm")
		add("uam/ssh-enrich")
	}
	if port > 0 {
		add("raw/basic-syn-check")
	}
	return out
}
