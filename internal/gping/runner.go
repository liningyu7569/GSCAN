package gping

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	uamservice "Going_Scan/internal/uam/service"
	"context"
	"fmt"
	"strings"
)

func Run(ctx context.Context, opts Options) (RunResult, error) {
	prepared, err := prepareRun(ctx, opts, true)
	if err != nil {
		return RunResult{}, err
	}

	target := prepared.Target
	actions := prepared.Actions
	templateName := prepared.TemplateName

	results := make([]stepResult, 0, len(actions))
	for _, action := range actions {
		allowed, err := shouldRunAction(action, results)
		if err != nil {
			return RunResult{}, err
		}
		if !allowed {
			results = append(results, stepResult{
				Action: action,
				Evidence: routeEvidence{
					RawStatus:       "skipped",
					ResponseSummary: fmt.Sprintf("condition not met: %s", action.When),
				},
			})
			continue
		}

		evidence, err := executeAction(ctx, target, action)
		if err != nil {
			if !action.ContinueOnError {
				return RunResult{}, err
			}
			evidence = routeEvidence{
				RawStatus: "error",
				ErrorText: err.Error(),
				Fields:    map[string]any{"continue_on_error": true},
				Extra:     map[string]any{"continue_on_error": true},
			}
		}
		results = append(results, stepResult{Action: action, Evidence: evidence})
	}

	reports := make([]ExecutionReport, 0, len(results))
	for _, item := range results {
		reports = append(reports, interpretEvidence(target, item.Action, item.Evidence))
	}
	if err := applyTemplateExtracts(target, prepared.Template, results, reports); err != nil {
		return RunResult{}, err
	}
	attachOperatorAssertions(reports, opts)
	recommendations, err := buildTemplateRecommendations(prepared.Template, results)
	if err != nil {
		return RunResult{}, err
	}

	result := RunResult{
		Target:          target,
		TemplateName:    templateName,
		Actions:         actions,
		Reports:         reports,
		Recommendations: recommendations,
	}

	if opts.WriteUAM && strings.TrimSpace(opts.UAMDBPath) != "" {
		runID, err := writeReportsToUAM(ctx, opts, target, reports)
		if err != nil {
			return RunResult{}, err
		}
		result.UAMRunID = runID
	}

	return result, nil
}

func attachOperatorAssertions(reports []ExecutionReport, opts Options) {
	last := lastWritableReport(reports)
	if last == nil {
		return
	}

	if state := normalizeVerificationState(opts.VerificationState); state != "" && state != domain.VerificationNone {
		subjectType := domain.SubjectHost
		if last.Port > 0 && last.Protocol != "icmp" {
			subjectType = domain.SubjectEndpoint
		}
		last.Claims = append(last.Claims, normalize.GPingClaimInput{
			SubjectType:   subjectType,
			Namespace:     "user",
			Name:          "verification_state",
			ValueText:     state,
			Confidence:    100,
			AssertionMode: domain.AssertionManual,
		})
	}

	if override := strings.TrimSpace(opts.OverrideService); override != "" && last.Port > 0 {
		last.Claims = append(last.Claims, normalize.GPingClaimInput{
			SubjectType:   domain.SubjectEndpoint,
			Namespace:     "user",
			Name:          "override_service_name",
			ValueText:     override,
			Confidence:    100,
			AssertionMode: domain.AssertionOverride,
		})
	}
}

func writeReportsToUAM(ctx context.Context, opts Options, target TargetContext, reports []ExecutionReport) (string, error) {
	metadata := uamservice.GPingRunMetadata{
		Command:  opts.Commandline,
		Targets:  []string{describeTarget(target)},
		Ports:    uniquePorts(reports),
		Profiles: uniqueProfiles(reports),
		Extra: map[string]any{
			"template":        opts.TemplateName,
			"source":          target.Source,
			"uam_endpoint":    target.UAMEndpointID,
			"current_service": target.CurrentService,
		},
	}

	ingester, err := uamservice.NewGPingIngester(ctx, opts.UAMDBPath, metadata)
	if err != nil {
		return "", err
	}

	for _, report := range reports {
		if report.RawStatus == "skipped" {
			continue
		}
		if err := ingester.IngestObservation(ctx, uamservice.GPingObservationInput{
			IP:              report.IP,
			Protocol:        report.Protocol,
			Port:            report.Port,
			RouteUsed:       report.RouteUsed,
			ActionType:      report.ActionType,
			RawMethod:       report.RawMethod,
			RawStatus:       report.RawStatus,
			RequestSummary:  report.RequestSummary,
			ResponseSummary: report.ResponseSummary,
			RTTMs:           report.RTTMs,
			ErrorText:       report.ErrorText,
			ExtraJSON:       report.ExtraJSON,
			Claims:          report.Claims,
		}); err != nil {
			return "", err
		}
	}

	runID := ingester.RunID()
	if err := ingester.Close(ctx); err != nil {
		return "", err
	}
	return runID, nil
}

func lastWritableReport(reports []ExecutionReport) *ExecutionReport {
	for index := len(reports) - 1; index >= 0; index-- {
		if reports[index].RawStatus == "skipped" {
			continue
		}
		return &reports[index]
	}
	return nil
}

func uniquePorts(reports []ExecutionReport) []int {
	seen := make(map[int]struct{})
	ports := make([]int, 0, len(reports))
	for _, report := range reports {
		if report.Port <= 0 {
			continue
		}
		if _, ok := seen[report.Port]; ok {
			continue
		}
		seen[report.Port] = struct{}{}
		ports = append(ports, report.Port)
	}
	return ports
}

func uniqueProfiles(reports []ExecutionReport) []string {
	seen := make(map[string]struct{})
	profiles := make([]string, 0, len(reports))
	for _, report := range reports {
		if report.RawStatus == "skipped" {
			continue
		}
		profile := fmt.Sprintf("%s/%s", report.RouteUsed, report.RawMethod)
		if _, ok := seen[profile]; ok {
			continue
		}
		seen[profile] = struct{}{}
		profiles = append(profiles, profile)
	}
	return profiles
}

func describeTarget(target TargetContext) string {
	if target.UAMEndpointID != "" {
		return target.UAMEndpointID
	}
	if target.URL != "" {
		return target.URL
	}
	if target.Port > 0 {
		return fmt.Sprintf("%s:%d/%s", target.IP, target.Port, target.Protocol)
	}
	return target.IP
}
