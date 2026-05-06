package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"context"
	"strings"
	"time"
)

// ModuleRunMetadata 模块运行元数据
type ModuleRunMetadata struct {
	Command string
	Targets []string
	Ports   []int
	Extra   map[string]any
}

// ModuleResultInput 模块的结构化产出输入
type ModuleResultInput struct {
	SchemaVersion string
	DataJSON      string
}

// ModuleObservationInput 模块单次探测的完整输入，含探测字段、Claim列表和ModuleResult列表
type ModuleObservationInput struct {
	IP              string
	Protocol        string
	Port            int
	ModuleName      string
	RouteUsed       string
	ActionType      string
	RawMethod       string
	RawStatus       string
	RequestSummary  string
	ResponseSummary string
	RTTMs           *float64
	ErrorText       string
	Claims          []normalize.ModuleClaimInput
	Results         []ModuleResultInput
}

// ModuleIngester 外部模块探测结果接入器
type ModuleIngester struct {
	*contractIngester
	moduleName string
}

// NewModuleIngester 创建ModuleIngester，初始化数据库并创建Run记录
func NewModuleIngester(ctx context.Context, dbPath string, moduleName string, metadata ModuleRunMetadata) (*ModuleIngester, error) {
	base, err := newContractIngester(ctx, dbPath, domain.ToolModule, moduleName, ContractRunMetadata{
		Command: metadata.Command,
		Targets: metadata.Targets,
		Ports:   metadata.Ports,
		Extra:   metadata.Extra,
	})
	if err != nil {
		return nil, err
	}

	return &ModuleIngester{
		contractIngester: base,
		moduleName:       moduleName,
	}, nil
}

// IngestObservation 将单条模块探测结果写入Observation、Claim、ModuleResult并刷新Projection
func (m *ModuleIngester) IngestObservation(ctx context.Context, input ModuleObservationInput) error {
	if m == nil || m.store == nil {
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

	moduleName := input.ModuleName
	if strings.TrimSpace(moduleName) == "" {
		moduleName = m.moduleName
	}

	observationID := m.store.NewObservationID()
	observation := domain.Observation{
		ObservationID:   observationID,
		RunID:           m.run.RunID,
		Tool:            domain.ToolModule,
		ModuleName:      moduleName,
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
		observation.ActionType = domain.ActionCollect
	}

	claims, err := normalize.ClaimsFromModule(observationID, host.HostID, endpointID, now, input.Claims, m.store.NewClaimID)
	if err != nil {
		return err
	}

	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := m.store.EnsureHost(ctx, tx, host); err != nil {
		return err
	}
	if endpointID != "" {
		if err := m.store.EnsureEndpoint(ctx, tx, endpoint); err != nil {
			return err
		}
	}
	if err := m.store.InsertObservation(ctx, tx, observation); err != nil {
		return err
	}
	if len(claims) > 0 {
		if err := m.store.InsertClaims(ctx, tx, claims); err != nil {
			return err
		}
		if err := refreshProjections(ctx, m.store, tx, observation, claims, host.HostID, endpointID); err != nil {
			return err
		}
	}

	for _, item := range input.Results {
		result := domain.ModuleResult{
			ModuleResultID: m.store.NewModuleResultID(),
			RunID:          m.run.RunID,
			ObservationID:  optionalString(observationID),
			SubjectType:    domain.SubjectEndpoint,
			SubjectID:      endpointID,
			ModuleName:     moduleName,
			SchemaVersion:  item.SchemaVersion,
			DataJSON:       item.DataJSON,
			CreatedAt:      now,
		}
		if endpointID == "" {
			result.SubjectType = domain.SubjectHost
			result.SubjectID = host.HostID
		}
		if err := m.store.InsertModuleResult(ctx, tx, result); err != nil {
			return err
		}
	}

	return tx.Commit()
}
