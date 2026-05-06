package service

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/project"
	sqlitestore "Going_Scan/internal/uam/store/sqlite"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// contractIngester 通用接入器基类，所有具体Ingester均内嵌此结构
type contractIngester struct {
	store *sqlitestore.Store
	run   domain.Run
}

// RunID 返回当前接入器的Run ID
func (c *contractIngester) RunID() string {
	if c == nil {
		return ""
	}
	return c.run.RunID
}

// ContractRunMetadata 通用Run元数据，所有工具接入时均需提供
type ContractRunMetadata struct {
	Command      string
	Targets      []string
	Ports        []int
	Profiles     []string
	ServiceScan  bool
	OutputFile   string
	OutputFormat string
	Extra        map[string]any
}

// newContractIngester 创建通用接入器，打开数据库、执行Migrate并创建Run记录
func newContractIngester(ctx context.Context, dbPath string, tool string, moduleName string, metadata ContractRunMetadata) (*contractIngester, error) {
	store, err := sqlitestore.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}

	now := time.Now().UTC()
	run, err := buildContractRun(store.NewRunID(), tool, moduleName, now, metadata)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.CreateRun(ctx, run); err != nil {
		_ = store.Close()
		return nil, err
	}

	return &contractIngester{
		store: store,
		run:   run,
	}, nil
}

// Close 标记Run结束并关闭数据库连接
func (c *contractIngester) Close(ctx context.Context) error {
	if c == nil || c.store == nil {
		return nil
	}
	finishedAt := time.Now().UTC()
	finishErr := c.store.FinishRun(ctx, c.run.RunID, finishedAt)
	closeErr := c.store.Close()
	if finishErr != nil {
		return finishErr
	}
	return closeErr
}

// refreshProjections 根据新Claim刷新Host和Endpoint的投影快照（内含优先级判断与写入）
func refreshProjections(ctx context.Context, store *sqlitestore.Store, tx *sql.Tx, observation domain.Observation, claims []domain.Claim, hostID string, endpointID string) error {
	hostGroup := project.SelectHostGroup(claims)
	if hostGroup != nil {
		current, meta, err := store.LoadHostProjection(ctx, tx, hostID)
		if err != nil {
			return err
		}
		var currentTime *time.Time
		currentMode := ""
		if meta != nil {
			currentMode = meta.AssertionMode
			currentTime = &meta.ClaimedAt
		}
		if project.ShouldApply(currentMode, currentTime, hostGroup.AssertionMode, hostGroup.ClaimedAt) {
			next, _ := project.ApplyHostProjection(current, observation, hostGroup)
			if err := store.SaveHostProjection(ctx, tx, next); err != nil {
				return err
			}
		}
	}

	if endpointID == "" {
		return nil
	}

	endpointGroup := project.SelectEndpointGroup(claims)
	if endpointGroup == nil {
		return nil
	}

	current, meta, err := store.LoadEndpointProjection(ctx, tx, endpointID)
	if err != nil {
		return err
	}
	var currentTime *time.Time
	currentMode := ""
	if meta != nil {
		currentMode = meta.AssertionMode
		currentTime = &meta.ClaimedAt
	}
	if !project.ShouldApply(currentMode, currentTime, endpointGroup.AssertionMode, endpointGroup.ClaimedAt) {
		return nil
	}

	next, _ := project.ApplyEndpointProjection(current, observation, endpointGroup)
	return store.SaveEndpointProjection(ctx, tx, next)
}

func buildContractRun(runID string, tool string, moduleName string, startedAt time.Time, metadata ContractRunMetadata) (domain.Run, error) {
	targetsJSON, err := marshalAnyJSON(metadata.Targets)
	if err != nil {
		return domain.Run{}, err
	}
	profilesJSON, err := marshalAnyJSON(metadata.Profiles)
	if err != nil {
		return domain.Run{}, err
	}
	portsJSON, err := marshalAnyJSON(metadata.Ports)
	if err != nil {
		return domain.Run{}, err
	}
	extra := map[string]any{
		"output_file":   metadata.OutputFile,
		"output_format": metadata.OutputFormat,
	}
	for key, value := range metadata.Extra {
		extra[key] = value
	}
	extraJSON, err := marshalAnyJSON(extra)
	if err != nil {
		return domain.Run{}, err
	}

	return domain.Run{
		RunID:        runID,
		Tool:         tool,
		ModuleName:   moduleName,
		Commandline:  metadata.Command,
		StartedAt:    startedAt,
		TargetsJSON:  targetsJSON,
		ProfilesJSON: profilesJSON,
		PortsJSON:    portsJSON,
		ServiceScan:  metadata.ServiceScan,
		ExtraJSON:    extraJSON,
	}, nil
}

func marshalAnyJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(raw), nil
}
