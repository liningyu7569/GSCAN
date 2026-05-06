package normalize

import (
	"Going_Scan/internal/uam/domain"
	"time"
)

// ModuleClaimInput 模块Claim输入，与GPingClaimInput一致
type ModuleClaimInput = GPingClaimInput

// ClaimsFromModule 将模块Claim输入转换为UAM Claim列表，复用ClaimsFromGPing逻辑
func ClaimsFromModule(observationID string, hostID string, endpointID string, claimedAt time.Time, inputs []ModuleClaimInput, nextClaimID func() string) ([]domain.Claim, error) {
	return ClaimsFromGPing(observationID, hostID, endpointID, claimedAt, inputs, nextClaimID)
}
