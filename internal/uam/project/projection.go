package project

import (
	"Going_Scan/internal/uam/domain"
	"sort"
	"time"
)

type HostGroup struct {
	Priority      int
	AssertionMode string
	ClaimedAt     time.Time
	Claims        []domain.Claim
}

type EndpointGroup struct {
	Priority      int
	AssertionMode string
	ClaimedAt     time.Time
	Claims        []domain.Claim
}

func ClaimPriority(mode string) int {
	switch mode {
	case domain.AssertionOverride:
		return 4
	case domain.AssertionManual:
		return 3
	case domain.AssertionObserved:
		return 2
	case domain.AssertionInferred:
		return 1
	default:
		return 0
	}
}

func SelectHostGroup(claims []domain.Claim) *HostGroup {
	relevant := make([]domain.Claim, 0, len(claims))
	for _, claim := range claims {
		if claim.SubjectType != domain.SubjectHost {
			continue
		}
		if claim.Namespace == "network" && claim.Name == "reachability" {
			relevant = append(relevant, claim)
			continue
		}
		if claim.Namespace == "user" && claim.Name == "verification_state" {
			relevant = append(relevant, claim)
		}
	}
	if len(relevant) == 0 {
		return nil
	}
	return buildGroup(relevant)
}

func SelectEndpointGroup(claims []domain.Claim) *EndpointGroup {
	relevant := make([]domain.Claim, 0, len(claims))
	for _, claim := range claims {
		if claim.SubjectType != domain.SubjectEndpoint {
			continue
		}
		switch {
		case claim.Namespace == "network" && claim.Name == "port_state":
			relevant = append(relevant, claim)
		case claim.Namespace == "service" && (claim.Name == "name" || claim.Name == "product" || claim.Name == "version" || claim.Name == "info" || claim.Name == "hostname" || claim.Name == "os" || claim.Name == "device" || claim.Name == "banner" || claim.Name == "cpes"):
			relevant = append(relevant, claim)
		case claim.Namespace == "user" && claim.Name == "verification_state":
			relevant = append(relevant, claim)
		}
	}
	if len(relevant) == 0 {
		return nil
	}

	group := buildGroup(relevant)
	return &EndpointGroup{
		Priority:      group.Priority,
		AssertionMode: group.AssertionMode,
		ClaimedAt:     group.ClaimedAt,
		Claims:        group.Claims,
	}
}

func ShouldApply(currentMode string, currentClaimedAt *time.Time, nextMode string, nextClaimedAt time.Time) bool {
	if currentMode == "" {
		return true
	}

	currentPriority := ClaimPriority(currentMode)
	nextPriority := ClaimPriority(nextMode)
	if nextPriority != currentPriority {
		return nextPriority > currentPriority
	}
	if currentClaimedAt == nil {
		return true
	}
	return !nextClaimedAt.Before(*currentClaimedAt)
}

func ApplyHostProjection(current domain.HostProjectionCurrent, observation domain.Observation, group *HostGroup) (domain.HostProjectionCurrent, bool) {
	if group == nil {
		return current, false
	}

	next := current
	for _, claim := range group.Claims {
		switch {
		case claim.Namespace == "network" && claim.Name == "reachability":
			next.CurrentReachability = claim.ValueText
			next.ReachabilityConfidence = intPtr(claim.Confidence)
		case claim.Namespace == "user" && claim.Name == "verification_state":
			if claim.ValueText != nil {
				next.VerificationState = *claim.ValueText
			}
		}
	}

	repClaimID := representativeClaimID(group.Claims)
	next.LastSeenAt = timePtr(observation.ObservedAt)
	next.LastClaimID = stringPtr(repClaimID)
	next.LastObservationID = stringPtr(observation.ObservationID)
	next.SourceTool = stringPtr(observation.Tool)
	if next.VerificationState == "" {
		next.VerificationState = domain.VerificationNone
	}

	return next, true
}

func ApplyEndpointProjection(current domain.EndpointProjectionCurrent, observation domain.Observation, group *EndpointGroup) (domain.EndpointProjectionCurrent, bool) {
	if group == nil {
		return current, false
	}

	next := current
	for _, claim := range group.Claims {
		switch {
		case claim.Namespace == "network" && claim.Name == "port_state":
			next.CurrentPortState = claim.ValueText
			next.PortStateConfidence = intPtr(claim.Confidence)
		case claim.Namespace == "service" && claim.Name == "name":
			next.CurrentService = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "product":
			next.CurrentProduct = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "version":
			next.CurrentVersion = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "info":
			next.CurrentInfo = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "hostname":
			next.CurrentHostname = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "os":
			next.CurrentOS = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "device":
			next.CurrentDevice = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "banner":
			next.CurrentBanner = claim.ValueText
		case claim.Namespace == "service" && claim.Name == "cpes":
			next.CurrentCPEsJSON = claim.ValueJSON
		case claim.Namespace == "user" && claim.Name == "verification_state":
			if claim.ValueText != nil {
				next.VerificationState = *claim.ValueText
			}
		}
	}

	repClaimID := representativeClaimID(group.Claims)
	next.LastSeenAt = timePtr(observation.ObservedAt)
	next.LastClaimID = stringPtr(repClaimID)
	next.LastObservationID = stringPtr(observation.ObservationID)
	next.SourceTool = stringPtr(observation.Tool)
	if next.VerificationState == "" {
		next.VerificationState = domain.VerificationNone
	}

	return next, true
}

func buildGroup(claims []domain.Claim) *HostGroup {
	if len(claims) == 0 {
		return nil
	}
	sorted := append([]domain.Claim(nil), claims...)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi := ClaimPriority(sorted[i].AssertionMode)
		pj := ClaimPriority(sorted[j].AssertionMode)
		if pi != pj {
			return pi > pj
		}
		return sorted[i].ClaimedAt.After(sorted[j].ClaimedAt)
	})

	best := sorted[0]
	return &HostGroup{
		Priority:      ClaimPriority(best.AssertionMode),
		AssertionMode: best.AssertionMode,
		ClaimedAt:     best.ClaimedAt,
		Claims:        claims,
	}
}

func representativeClaimID(claims []domain.Claim) string {
	bestID := ""
	bestPriority := -1
	var bestTime time.Time

	for _, claim := range claims {
		priority := ClaimPriority(claim.AssertionMode)
		if priority > bestPriority || (priority == bestPriority && claim.ClaimedAt.After(bestTime)) {
			bestPriority = priority
			bestTime = claim.ClaimedAt
			bestID = claim.ClaimID
		}
	}

	return bestID
}

func intPtr(v int) *int {
	value := v
	return &value
}

func stringPtr(v string) *string {
	value := v
	return &value
}

func timePtr(v time.Time) *time.Time {
	value := v
	return &value
}
