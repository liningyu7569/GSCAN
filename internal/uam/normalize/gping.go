package normalize

import (
	"Going_Scan/internal/uam/domain"
	"fmt"
	"strings"
	"time"
)

// GPingClaimInput gping/模块接入时外部传入的单条Claim输入
type GPingClaimInput struct {
	SubjectType   string
	Namespace     string
	Name          string
	ValueText     string
	ValueJSON     string
	Confidence    int
	AssertionMode string
}

// ClaimsFromGPing 将gping外部Claim输入转换为UAM Claim列表，含默认置信度和subject解析
func ClaimsFromGPing(observationID string, hostID string, endpointID string, claimedAt time.Time, inputs []GPingClaimInput, nextClaimID func() string) ([]domain.Claim, error) {
	claims := make([]domain.Claim, 0, len(inputs)+1)

	for _, input := range inputs {
		subjectType, subjectID, err := resolveSubject(input.SubjectType, hostID, endpointID)
		if err != nil {
			return nil, err
		}

		if input.Confidence == 0 {
			input.Confidence = 80
		}
		if input.AssertionMode == "" {
			input.AssertionMode = domain.AssertionObserved
		}

		claim := domain.Claim{
			ClaimID:       nextClaimID(),
			ObservationID: observationID,
			SubjectType:   subjectType,
			SubjectID:     subjectID,
			Namespace:     input.Namespace,
			Name:          input.Name,
			Confidence:    input.Confidence,
			AssertionMode: input.AssertionMode,
			ClaimedAt:     claimedAt.UTC(),
		}
		if input.ValueText != "" {
			value := input.ValueText
			claim.ValueText = &value
		}
		if input.ValueJSON != "" {
			value := input.ValueJSON
			claim.ValueJSON = &value
		}
		claims = append(claims, claim)

		if input.Namespace == "user" && input.Name == "override_service_name" && endpointID != "" && strings.TrimSpace(input.ValueText) != "" {
			overrideValue := strings.TrimSpace(input.ValueText)
			claims = append(claims, domain.Claim{
				ClaimID:       nextClaimID(),
				ObservationID: observationID,
				SubjectType:   domain.SubjectEndpoint,
				SubjectID:     endpointID,
				Namespace:     "service",
				Name:          "name",
				ValueText:     &overrideValue,
				Confidence:    input.Confidence,
				AssertionMode: domain.AssertionOverride,
				ClaimedAt:     claimedAt.UTC(),
			})
		}
	}

	return claims, nil
}

// resolveSubject 根据subjectType决定生效主体类型和ID
func resolveSubject(subjectType string, hostID string, endpointID string) (string, string, error) {
	switch subjectType {
	case "", domain.SubjectEndpoint:
		if endpointID == "" {
			return "", "", fmt.Errorf("endpoint subject requires endpoint identity")
		}
		return domain.SubjectEndpoint, endpointID, nil
	case domain.SubjectHost:
		return domain.SubjectHost, hostID, nil
	default:
		return "", "", fmt.Errorf("unsupported subject type %q", subjectType)
	}
}
