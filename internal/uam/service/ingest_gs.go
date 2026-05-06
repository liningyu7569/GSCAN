package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"strings"
	"time"
)

// RunMetadata GS运行元数据，描述一次gs扫描的配置信息
type RunMetadata struct {
	Command      string
	Targets      []string
	Ports        []int
	Profiles     []string
	ServiceScan  bool
	OutputFile   string
	OutputFormat string
}

// ScanResult GS单条L4/L7扫描结果
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

// GSIngester GS扫描结果接入器，负责将GS的L4/L7发现写入UAM的五层对象模型
type GSIngester struct {
	*contractIngester
}

// NewGSIngester 创建GSIngester，初始化数据库并创建Run记录
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

// IngestResult 将单条L4扫描结果写入Observation、Claim并刷新Projection
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

// IngestServiceResult 仅写入服务识别Claim（service/product/version等），不覆盖端口状态
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

// GSDiscoveryResult GS主机发现结果
type GSDiscoveryResult struct {
	IP       string
	Method   string
	Status   string
	Protocol string
}

// IngestDiscovery 写入GS主机发现结果（纯主机级可达性）
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
