package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"strings"
	"time"
)

type RunMetadata struct {
	Command      string
	Targets      []string
	Ports        []int
	Profiles     []string
	ServiceScan  bool
	OutputFile   string
	OutputFormat string
}

type ScanResult struct {
	IP       string
	Port     int
	Protocol string
	Method   string
	State    string
	Service  string
	Product  string
	Version  string
	Info     string
	Hostname string
	OS       string
	Device   string
	CPEs     []string
	Banner   string
}

type GSIngester struct {
	*contractIngester
}

func NewGSIngester(ctx context.Context, dbPath string, metadata RunMetadata) (*GSIngester, error) {
	base, err := newContractIngester(ctx, dbPath, domain.ToolGS, domain.ModuleNameGS, ContractRunMetadata{
		Command:      metadata.Command,
		Targets:      metadata.Targets,
		Ports:        metadata.Ports,
		Profiles:     metadata.Profiles,
		ServiceScan:  metadata.ServiceScan,
		OutputFile:   metadata.OutputFile,
		OutputFormat: metadata.OutputFormat,
	})
	if err != nil {
		return nil, err
	}

	return &GSIngester{contractIngester: base}, nil
}

func (g *GSIngester) IngestResult(ctx context.Context, result ScanResult) error {
	if g == nil || g.store == nil {
		return nil
	}

	now := time.Now().UTC()
	host := domain.Host{
		HostID:      domain.HostIDFromIP(result.IP),
		IP:          result.IP,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	var (
		endpoint   domain.Endpoint
		endpointID string
	)
	if result.Protocol != "" && result.Port > 0 {
		endpointID = domain.EndpointID(host.HostID, result.Protocol, result.Port)
		endpoint = domain.Endpoint{
			EndpointID:  endpointID,
			HostID:      host.HostID,
			Protocol:    strings.ToLower(result.Protocol),
			Port:        result.Port,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
	}

	observationID := g.store.NewObservationID()
	observation, err := normalize.ObservationFromGS(
		g.run.RunID,
		host.HostID,
		endpointID,
		observationID,
		now,
		normalize.GSResult(result),
	)
	if err != nil {
		return err
	}

	claims := normalize.ClaimsFromGS(
		observation,
		host.HostID,
		endpointID,
		now,
		normalize.GSResult(result),
		g.store.NewClaimID,
	)

	tx, err := g.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := g.store.EnsureHost(ctx, tx, host); err != nil {
		return err
	}
	if endpointID != "" {
		if err := g.store.EnsureEndpoint(ctx, tx, endpoint); err != nil {
			return err
		}
	}
	if err := g.store.InsertObservation(ctx, tx, observation); err != nil {
		return err
	}
	if err := g.store.InsertClaims(ctx, tx, claims); err != nil {
		return err
	}
	if err := refreshProjections(ctx, g.store, tx, observation, claims, host.HostID, endpointID); err != nil {
		return err
	}

	return tx.Commit()
}

func (g *GSIngester) IngestServiceResult(ctx context.Context, result ScanResult) error {
	if g == nil || g.store == nil {
		return nil
	}

	now := time.Now().UTC()
	host := domain.Host{
		HostID:      domain.HostIDFromIP(result.IP),
		IP:          result.IP,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if result.Protocol == "" || result.Port <= 0 {
		return nil
	}

	endpointID := domain.EndpointID(host.HostID, result.Protocol, result.Port)
	endpoint := domain.Endpoint{
		EndpointID:  endpointID,
		HostID:      host.HostID,
		Protocol:    strings.ToLower(result.Protocol),
		Port:        result.Port,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	observationID := g.store.NewObservationID()
	observation, err := normalize.ObservationFromGS(
		g.run.RunID,
		host.HostID,
		endpointID,
		observationID,
		now,
		normalize.GSResult(result),
	)
	if err != nil {
		return err
	}

	claims := normalize.ServiceClaimsFromGS(
		observation,
		endpointID,
		now,
		normalize.GSResult(result),
		g.store.NewClaimID,
	)
	if len(claims) == 0 {
		return nil
	}

	tx, err := g.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := g.store.EnsureHost(ctx, tx, host); err != nil {
		return err
	}
	if err := g.store.EnsureEndpoint(ctx, tx, endpoint); err != nil {
		return err
	}
	if err := g.store.InsertObservation(ctx, tx, observation); err != nil {
		return err
	}
	if err := g.store.InsertClaims(ctx, tx, claims); err != nil {
		return err
	}
	if err := refreshProjections(ctx, g.store, tx, observation, claims, host.HostID, endpointID); err != nil {
		return err
	}

	return tx.Commit()
}

type GSDiscoveryResult struct {
	IP       string
	Method   string
	Status   string
	Protocol string
}

func (g *GSIngester) IngestDiscovery(ctx context.Context, discovery GSDiscoveryResult) error {
	if g == nil || g.store == nil {
		return nil
	}

	now := time.Now().UTC()
	host := domain.Host{
		HostID:      domain.HostIDFromIP(discovery.IP),
		IP:          discovery.IP,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	observationID := g.store.NewObservationID()
	observation, err := normalize.ObservationFromGSDiscovery(
		g.run.RunID,
		host.HostID,
		observationID,
		now,
		normalize.GSDiscovery(discovery),
	)
	if err != nil {
		return err
	}

	claims := normalize.ClaimsFromGSDiscovery(
		observation,
		host.HostID,
		now,
		normalize.GSDiscovery(discovery),
		g.store.NewClaimID,
	)

	tx, err := g.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := g.store.EnsureHost(ctx, tx, host); err != nil {
		return err
	}
	if err := g.store.InsertObservation(ctx, tx, observation); err != nil {
		return err
	}
	if err := g.store.InsertClaims(ctx, tx, claims); err != nil {
		return err
	}
	if err := refreshProjections(ctx, g.store, tx, observation, claims, host.HostID, ""); err != nil {
		return err
	}

	return tx.Commit()
}
