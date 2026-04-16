package gping

import (
	sqlitestore "Going_Scan/internal/uam/store/sqlite"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
)

func ResolveTarget(ctx context.Context, opts Options) (TargetContext, error) {
	if strings.TrimSpace(opts.UAMEndpoint) != "" {
		target, err := resolveFromUAMEndpoint(ctx, opts.UAMDBPath, opts.UAMEndpoint)
		if err != nil {
			return TargetContext{}, err
		}
		return applyTargetOverrides(target, opts), nil
	}
	if hasUAMSelectionFilters(opts) {
		target, err := resolveFromUAMFilters(ctx, opts)
		if err != nil {
			return TargetContext{}, err
		}
		return applyTargetOverrides(target, opts), nil
	}
	if strings.TrimSpace(opts.URL) != "" {
		target, err := resolveFromURL(opts.URL, opts)
		if err != nil {
			return TargetContext{}, err
		}
		return applyTargetOverrides(target, opts), nil
	}
	if strings.TrimSpace(opts.IP) != "" {
		target := TargetContext{
			IP:       strings.TrimSpace(opts.IP),
			Port:     opts.Port,
			Protocol: normalizeProtocol(opts.Protocol),
			Host:     strings.TrimSpace(opts.HostHeader),
			Source:   "literal",
		}
		if target.Protocol == "" {
			target.Protocol = "tcp"
		}
		if target.Port <= 0 && target.Protocol != "icmp" {
			return TargetContext{}, fmt.Errorf("port is required for literal non-icmp target")
		}
		if target.Protocol == "icmp" {
			target.Port = 0
		}
		target.HostHeader = strings.TrimSpace(opts.HostHeader)
		target.SNI = strings.TrimSpace(opts.SNI)
		target.Path = stringValue(opts.Path, "/")
		if target.Host == "" {
			target.Host = target.IP
		}
		if target.HostHeader == "" {
			target.HostHeader = target.Host
		}
		if target.SNI == "" && target.Host != target.IP {
			target.SNI = target.Host
		}
		if target.Port > 0 {
			target.Scheme = inferScheme(target.Port, target.SNI)
			target.URL = buildURLString(target.Scheme, target.HostHeader, target.Port, target.Path)
		}
		if opts.UAMDBPath != "" && target.Port > 0 {
			if hydrated, err := tryHydrateFromUAM(ctx, opts.UAMDBPath, target); err == nil {
				target.CurrentService = hydrated.CurrentService
				target.CurrentProduct = hydrated.CurrentProduct
				target.CurrentVersion = hydrated.CurrentVersion
				target.CurrentBanner = hydrated.CurrentBanner
				target.VerificationState = hydrated.VerificationState
				target.UAMEndpointID = hydrated.UAMEndpointID
			}
		}
		return applyTargetOverrides(target, opts), nil
	}
	return TargetContext{}, fmt.Errorf("target is required: use --url, --ip/--port, or --uam-endpoint")
}

func resolveFromURL(raw string, opts Options) (TargetContext, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return TargetContext{}, fmt.Errorf("parse url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return TargetContext{}, fmt.Errorf("url must include scheme and host")
	}

	host := parsed.Hostname()
	ip, err := resolveHostToIPv4(host)
	if err != nil {
		return TargetContext{}, err
	}
	port := 0
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}
	if port == 0 {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = 443
		default:
			port = 80
		}
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path = path + "?" + parsed.RawQuery
	}

	target := TargetContext{
		IP:         ip,
		Port:       port,
		Protocol:   "tcp",
		Scheme:     strings.ToLower(parsed.Scheme),
		Host:       host,
		HostHeader: stringValue(opts.HostHeader, host),
		SNI:        stringValue(opts.SNI, host),
		URL:        parsed.String(),
		Path:       path,
		Source:     "url",
	}
	if target.HostHeader == "" {
		target.HostHeader = host
	}
	return target, nil
}

func resolveFromUAMEndpoint(ctx context.Context, dbPath string, endpointID string) (TargetContext, error) {
	if strings.TrimSpace(dbPath) == "" {
		return TargetContext{}, fmt.Errorf("--uam-db is required when using --uam-endpoint")
	}

	store, err := sqlitestore.OpenExisting(dbPath)
	if err != nil {
		return TargetContext{}, err
	}
	defer store.Close()

	row := store.DB().QueryRowContext(ctx, `
SELECT endpoint_id, ip, protocol, port, current_service, verification_state, current_product, current_version, current_banner
FROM v_endpoint_assets
WHERE endpoint_id = ?`, strings.TrimSpace(endpointID))

	var target TargetContext
	var currentService sql.NullString
	var currentProduct sql.NullString
	var currentVersion sql.NullString
	var currentBanner sql.NullString
	if err := row.Scan(
		&target.UAMEndpointID,
		&target.IP,
		&target.Protocol,
		&target.Port,
		&currentService,
		&target.VerificationState,
		&currentProduct,
		&currentVersion,
		&currentBanner,
	); err != nil {
		if err == sql.ErrNoRows {
			return TargetContext{}, fmt.Errorf("no UAM endpoint found for %s", endpointID)
		}
		return TargetContext{}, err
	}
	target.Protocol = normalizeProtocol(target.Protocol)
	target.Source = "uam"
	target.CurrentService = strings.TrimSpace(currentService.String)
	target.CurrentProduct = strings.TrimSpace(currentProduct.String)
	target.CurrentVersion = strings.TrimSpace(currentVersion.String)
	target.CurrentBanner = strings.TrimSpace(currentBanner.String)
	target.Scheme = inferScheme(target.Port, "")
	target.Path = "/"
	target.Host = target.IP
	target.HostHeader = target.IP
	target.URL = buildURLString(target.Scheme, target.IP, target.Port, target.Path)
	return target, nil
}

func resolveFromUAMFilters(ctx context.Context, opts Options) (TargetContext, error) {
	candidates, err := ListCandidates(ctx, opts, 11)
	if err != nil {
		return TargetContext{}, err
	}
	if len(candidates) == 0 {
		return TargetContext{}, fmt.Errorf("no UAM endpoint matched the supplied filters")
	}
	if opts.PickIndex > 0 {
		index := opts.PickIndex - 1
		if index < 0 || index >= len(candidates) {
			return TargetContext{}, fmt.Errorf("--pick-index=%d is out of range for %d matched candidates", opts.PickIndex, len(candidates))
		}
		return candidateToTarget(candidates[index]), nil
	}
	if len(candidates) > 1 && !opts.PickFirst {
		sample := make([]string, 0, len(candidates))
		for index, item := range candidates {
			sample = append(sample, fmt.Sprintf("%d:%s (%s, verify=%s)", index+1, item.EndpointID, item.CurrentService, item.VerificationState))
		}
		return TargetContext{}, fmt.Errorf("multiple UAM endpoints matched; refine the filters or use --pick-first/--pick-index, or inspect them with `goscan gping candidates`: %s", strings.Join(sample, "; "))
	}
	return candidateToTarget(candidates[0]), nil
}

func candidateToTarget(item Candidate) TargetContext {
	target := TargetContext{
		UAMEndpointID:     item.EndpointID,
		IP:                item.IP,
		Protocol:          normalizeProtocol(item.Protocol),
		Port:              item.Port,
		Source:            "uam-query",
		CurrentService:    item.CurrentService,
		CurrentProduct:    item.CurrentProduct,
		CurrentVersion:    item.CurrentVersion,
		CurrentBanner:     item.CurrentBanner,
		VerificationState: item.VerificationState,
		Scheme:            inferScheme(item.Port, ""),
		Path:              "/",
		Host:              item.IP,
		HostHeader:        item.IP,
	}
	target.URL = buildURLString(target.Scheme, target.IP, target.Port, target.Path)
	return target
}

func tryHydrateFromUAM(ctx context.Context, dbPath string, target TargetContext) (TargetContext, error) {
	store, err := sqlitestore.OpenExisting(dbPath)
	if err != nil {
		return TargetContext{}, err
	}
	defer store.Close()

	row := store.DB().QueryRowContext(ctx, `
SELECT endpoint_id, current_service, verification_state, current_product, current_version, current_banner
FROM v_endpoint_assets
WHERE ip = ? AND protocol = ? AND port = ?
LIMIT 1`, target.IP, normalizeProtocol(target.Protocol), target.Port)

	var hydrated TargetContext
	var service sql.NullString
	var product sql.NullString
	var version sql.NullString
	var banner sql.NullString
	if err := row.Scan(&hydrated.UAMEndpointID, &service, &hydrated.VerificationState, &product, &version, &banner); err != nil {
		return TargetContext{}, err
	}
	hydrated.CurrentService = strings.TrimSpace(service.String)
	hydrated.CurrentProduct = strings.TrimSpace(product.String)
	hydrated.CurrentVersion = strings.TrimSpace(version.String)
	hydrated.CurrentBanner = strings.TrimSpace(banner.String)
	return hydrated, nil
}

func hasUAMSelectionFilters(opts Options) bool {
	return strings.TrimSpace(opts.UAMService) != "" ||
		strings.TrimSpace(opts.UAMVerify) != "" ||
		opts.PickFirst ||
		opts.PickIndex > 0
}

func applyTargetOverrides(target TargetContext, opts Options) TargetContext {
	if host := strings.TrimSpace(opts.HostHeader); host != "" {
		target.Host = host
		target.HostHeader = host
	}
	if sni := strings.TrimSpace(opts.SNI); sni != "" {
		target.SNI = sni
	}
	if target.Host == "" {
		target.Host = target.IP
	}
	if target.HostHeader == "" {
		target.HostHeader = target.Host
	}
	if target.SNI == "" && target.Host != "" && net.ParseIP(target.Host) == nil {
		target.SNI = target.Host
	}
	if path := strings.TrimSpace(opts.Path); path != "" {
		target.Path = path
	}
	if target.Path == "" {
		target.Path = "/"
	}
	if target.Scheme == "" {
		target.Scheme = inferScheme(target.Port, target.SNI)
	}
	if target.Port > 0 && (target.URL == "" || strings.TrimSpace(opts.Path) != "" || strings.TrimSpace(opts.HostHeader) != "" || strings.TrimSpace(opts.SNI) != "") {
		host := target.HostHeader
		if host == "" {
			host = target.Host
		}
		target.URL = buildURLString(target.Scheme, host, target.Port, target.Path)
	}
	return target
}

func inferScheme(port int, sni string) string {
	switch {
	case strings.TrimSpace(sni) != "":
		return "https"
	case port == 443 || port == 8443:
		return "https"
	default:
		return "http"
	}
}
