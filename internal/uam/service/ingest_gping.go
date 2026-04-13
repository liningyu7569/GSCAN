package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"strings"
	"time"
)

type GPingRunMetadata struct {
	Command  string
	Targets  []string
	Profiles []string
	Ports    []int
	Extra    map[string]any
}

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
	Claims          []normalize.GPingClaimInput
}

type GPingIngester struct {
	*contractIngester
}

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
