package normalize

import (
	"Going_Scan/internal/uam/domain"
	"time"
)

type ModuleClaimInput = GPingClaimInput

func ClaimsFromModule(observationID string, hostID string, endpointID string, claimedAt time.Time, inputs []ModuleClaimInput, nextClaimID func() string) ([]domain.Claim, error) {
	return ClaimsFromGPing(observationID, hostID, endpointID, claimedAt, inputs, nextClaimID)
}
