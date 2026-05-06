package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"strings"
	"time"
)

// GPingRunMetadata gping运行元数据
type GPingRunMetadata struct {
	Command  string
	Targets  []string
	Profiles []string
	Ports    []int
	Extra    map[string]any
}

// GPingObservationInput gping单次探测的完整输入，含原始探测字段和Claim列表
type GPingObservationInput struct {
	IP              string
	Protocol        string
	Port            int
	RouteUsed       string
	ActionType      string
	RawMethod       string
	RawStatus       string
	RequestSummary  string
	ResponseSummary string
	RTTMs           *float64
	ErrorText       string
	ExtraJSON       string
	Claims          []normalize.GPingClaimInput
}

// GPingIngester gping探测结果接入器
type GPingIngester struct {
	*contractIngester
}

// NewGPingIngester 创建GPingIngester，初始化数据库并创建Run记录
func NewGPingIngester(ctx context.Context, dbPath string, metadata GPingRunMetadata) (*GPingIngester, error) {
	base, err := newContractIngester(ctx, dbPath, domain.ToolGPing, "gping", ContractRunMetadata{
		Command:  metadata.Command,
		Targets:  metadata.Targets,
		Ports:    metadata.Ports,
		Profiles: metadata.Profiles,
		Extra:    metadata.Extra,
	})
	if err != nil {
		return nil, err
	}

	return &GPingIngester{contractIngester: base}, nil
}

// IngestObservation 将单条gping探测结果写入Observation、Claim并刷新Projection
func (g *GPingIngester) IngestObservation(ctx context.Context, input GPingObservationInput) error {
	if g == nil || g.store == nil {
		return nil
	}

	now := time.Now().UTC()
	host := domain.Host{
		HostID:      domain.HostIDFromIP(input.IP),
		IP:          input.IP,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	var (
		endpoint   domain.Endpoint
		endpointID string
	)
	if input.Protocol != "" && input.Port > 0 {
		endpointID = domain.EndpointID(host.HostID, input.Protocol, input.Port)
		endpoint = domain.Endpoint{
			EndpointID:  endpointID,
			HostID:      host.HostID,
			Protocol:    strings.ToLower(input.Protocol),
			Port:        input.Port,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
	}

	observationID := g.store.NewObservationID()
	observation := domain.Observation{
		ObservationID:   observationID,
		RunID:           g.run.RunID,
		Tool:            domain.ToolGPing,
		ModuleName:      "gping",
		HostID:          host.HostID,
		EndpointID:      optionalString(endpointID),
		RouteUsed:       optionalString(strings.TrimSpace(input.RouteUsed)),
		ActionType:      input.ActionType,
		RawMethod:       input.RawMethod,
		RawStatus:       input.RawStatus,
		RequestSummary:  input.RequestSummary,
		ResponseSummary: input.ResponseSummary,
		RTTMs:           input.RTTMs,
		ErrorText:       input.ErrorText,
		ObservedAt:      now,
		ExtraJSON:       input.ExtraJSON,
	}
	if observation.ActionType == "" {
		observation.ActionType = domain.ActionProbe
	}

	claims, err := normalize.ClaimsFromGPing(observationID, host.HostID, endpointID, now, input.Claims, g.store.NewClaimID)
	if err != nil {
		return err
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
	if endpointID != "" {
		if err := g.store.EnsureEndpoint(ctx, tx, endpoint); err != nil {
			return err
		}
	}
	if err := g.store.InsertObservation(ctx, tx, observation); err != nil {
		return err
	}
	if len(claims) > 0 {
		if err := g.store.InsertClaims(ctx, tx, claims); err != nil {
			return err
		}
		if err := refreshProjections(ctx, g.store, tx, observation, claims, host.HostID, endpointID); err != nil {
			return err
		}
	}

	return tx.Commit()
}
