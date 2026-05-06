package gping

import (
	"Going_Scan/internal/uam/domain"
	"Going_Scan/internal/uam/normalize"
	"encoding/json"
	"fmt"
	"strings"
)

// preparedRun 封装一次模板执行前的完整准备上下文
type preparedRun struct {
	Target             TargetContext
	TemplateName       string
	Template           *TemplateSpec
	Actions            []ActionUnit
	SuggestedTemplates []string
	TemplateSuggest    map[string]string
	TemplateRecommend  map[string]string
	OperatorAssertions []string
	WriteUAM           bool
}

// stepResult 记录单个模板步骤的执行结果与证据
type stepResult struct {
	Action   ActionUnit
	Evidence routeEvidence
}

// buildPreviewResult 将 preparedRun 转换为对外暴露的 PreviewResult
func buildPreviewResult(prepared preparedRun) PreviewResult {
	return PreviewResult{
		Target:             prepared.Target,
		TemplateName:       prepared.TemplateName,
		Actions:            prepared.Actions,
		SuggestedTemplates: prepared.SuggestedTemplates,
		TemplateSuggest:    cloneStringMap(prepared.TemplateSuggest),
		TemplateRecommend:  cloneStringMap(prepared.TemplateRecommend),
		OperatorAssertions: append([]string(nil), prepared.OperatorAssertions...),
		WriteUAM:           prepared.WriteUAM,
	}
}

// shouldRunAction 根据 when 条件判断当前动作是否应该执行
func shouldRunAction(action ActionUnit, results []stepResult) (bool, error) {
	when := strings.TrimSpace(action.When)
	if when == "" {
		return true, nil
	}
	return evaluateCondition(when, results)
}

// evaluateCondition 计算 DSL 条件表达式（contains, ==, !=, exists）
func evaluateCondition(expression string, results []stepResult) (bool, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return true, nil
	}

	for _, operator := range []string{" contains ", " == ", " !=", " exists"} {
		if !strings.Contains(expression, operator) {
			continue
		}
		parts := strings.SplitN(expression, operator, 2)
		left := resolveConditionPath(parts[0], results)
		right := ""
		if len(parts) == 2 {
			right = trimConditionLiteral(parts[1])
		}

		switch strings.TrimSpace(operator) {
		case "contains":
			return strings.Contains(stringAny(left), right), nil
		case "==":
			return stringAny(left) == right, nil
		case "!=":
			return stringAny(left) != right, nil
		case "exists":
			return left != nil && stringAny(left) != "", nil
		}
	}

	value := resolveConditionPath(expression, results)
	text := strings.TrimSpace(stringAny(value))
	return text != "" && !strings.EqualFold(text, "false") && text != "0", nil
}

func resolveConditionPath(path string, results []stepResult) any {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	if len(parts) < 2 {
		return nil
	}
	stepID := normalizeStepID(parts[0])
	var result *stepResult
	for index := range results {
		if results[index].Action.ID == stepID {
			result = &results[index]
			break
		}
	}
	if result == nil {
		return nil
	}

	switch parts[1] {
	case "raw_status":
		return result.Evidence.RawStatus
	case "request_summary":
		return result.Evidence.RequestSummary
	case "response_summary":
		return result.Evidence.ResponseSummary
	case "error_text":
		return result.Evidence.ErrorText
	case "fields":
		return nestedMapValue(result.Evidence.Fields, parts[2:])
	case "extra":
		return nestedMapValue(result.Evidence.Extra, parts[2:])
	default:
		return resolveEvidenceField(result.Evidence, strings.Join(parts[1:], "."))
	}
}

func trimConditionLiteral(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, `"`)
	value = strings.TrimSuffix(value, `"`)
	value = strings.TrimPrefix(value, `'`)
	value = strings.TrimSuffix(value, `'`)
	return value
}

// applyTemplateExtracts 根据模板的 extract 规则从步骤结果中提取声明
func applyTemplateExtracts(target TargetContext, spec *TemplateSpec, results []stepResult, reports []ExecutionReport) error {
	if spec == nil || len(spec.Extract) == 0 {
		return nil
	}

	indexByStep := make(map[string]int, len(results))
	for index, item := range results {
		indexByStep[item.Action.ID] = index
	}

	for _, rule := range spec.Extract {
		stepID := normalizeStepID(rule.From)
		index, ok := indexByStep[stepID]
		if !ok {
			return fmt.Errorf("template %q extract references unknown step %q", spec.Name, rule.From)
		}
		value := resolveEvidenceField(results[index].Evidence, rule.Field)
		if value == nil || stringAny(value) == "" {
			continue
		}
		claim, err := buildExtractClaim(target, rule, value)
		if err != nil {
			return fmt.Errorf("template %q extract %s failed: %w", spec.Name, rule.ToClaim, err)
		}
		reports[index].Claims = appendClaimIfMissing(reports[index].Claims, claim)
	}

	return nil
}

func buildExtractClaim(target TargetContext, rule TemplateExtractSpec, value any) (normalize.GPingClaimInput, error) {
	namespace, name, ok := strings.Cut(strings.TrimSpace(rule.ToClaim), ".")
	if !ok || namespace == "" || name == "" {
		return normalize.GPingClaimInput{}, fmt.Errorf("invalid to_claim %q", rule.ToClaim)
	}

	subjectType := strings.TrimSpace(rule.SubjectType)
	if subjectType == "" {
		if target.Port > 0 && target.Protocol != "icmp" {
			subjectType = domain.SubjectEndpoint
		} else {
			subjectType = domain.SubjectHost
		}
	}
	mode := strings.TrimSpace(rule.AssertionMode)
	if mode == "" {
		mode = domain.AssertionObserved
	}
	confidence := rule.Confidence
	if confidence <= 0 {
		confidence = 76
	}

	claim := normalize.GPingClaimInput{
		SubjectType:   subjectType,
		Namespace:     namespace,
		Name:          name,
		Confidence:    confidence,
		AssertionMode: mode,
	}

	switch typed := value.(type) {
	case bool:
		claim.ValueText = fmt.Sprintf("%t", typed)
	case string:
		claim.ValueText = typed
	case []string, []any, map[string]any, map[string]string:
		raw, err := json.Marshal(typed)
		if err != nil {
			return normalize.GPingClaimInput{}, err
		}
		claim.ValueJSON = string(raw)
	default:
		claim.ValueText = stringAny(value)
	}

	return claim, nil
}

// buildTemplateRecommendations 根据模板 recommend 规则和步骤结果生成资产归类建议
func buildTemplateRecommendations(spec *TemplateSpec, results []stepResult) ([]Recommendation, error) {
	if spec == nil {
		return nil, nil
	}

	values := spec.Recommend.ResolvedValues()
	if len(values) == 0 {
		return nil, nil
	}
	for _, condition := range spec.Recommend.WhenAll {
		matched, err := evaluateCondition(condition, results)
		if err != nil {
			return nil, err
		}
		if !matched {
			return nil, nil
		}
	}

	recommendation := Recommendation{
		VerificationState: strings.TrimSpace(values["verification_state"]),
		OverrideService:   strings.TrimSpace(values["override_service_name"]),
	}
	reason := strings.Join(spec.Recommend.WhenAll, " && ")
	if reason == "" {
		reason = "template recommendation"
	}
	recommendation.Reason = reason

	if recommendation.VerificationState == "" && recommendation.OverrideService == "" {
		return nil, nil
	}
	return []Recommendation{recommendation}, nil
}

func resolveEvidenceField(evidence routeEvidence, field string) any {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}
	if strings.HasPrefix(field, "fields.") {
		return nestedMapValue(evidence.Fields, strings.Split(strings.TrimPrefix(field, "fields."), "."))
	}
	if strings.HasPrefix(field, "extra.") {
		return nestedMapValue(evidence.Extra, strings.Split(strings.TrimPrefix(field, "extra."), "."))
	}
	if value, ok := evidence.Fields[field]; ok {
		return value
	}
	if value, ok := evidence.Extra[field]; ok {
		return value
	}
	switch field {
	case "raw_status":
		return evidence.RawStatus
	case "request_summary":
		return evidence.RequestSummary
	case "response_summary":
		return evidence.ResponseSummary
	case "error_text":
		return evidence.ErrorText
	case "status_code":
		return evidence.StatusCode
	case "server":
		return evidence.Server
	case "location":
		return evidence.Location
	case "title":
		return evidence.Title
	case "body_preview":
		return evidence.BodyPreview
	case "banner":
		return evidence.Banner
	case "product":
		return evidence.Product
	case "version":
		return evidence.Version
	case "tls_subject":
		return evidence.TLSSubject
	case "tls_issuer":
		return evidence.TLSIssuer
	case "tls_san":
		return evidence.TLSSANs
	case "tls_alpn":
		return evidence.TLSALPN
	case "tls_version":
		return evidence.TLSVersion
	default:
		return nil
	}
}

func nestedMapValue(root map[string]any, path []string) any {
	if len(path) == 0 {
		return root
	}
	var current any = root
	for _, part := range path {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case map[string]string:
			current = typed[part]
		default:
			return nil
		}
	}
	return current
}

func appendClaimIfMissing(claims []normalize.GPingClaimInput, next normalize.GPingClaimInput) []normalize.GPingClaimInput {
	for _, existing := range claims {
		if existing.SubjectType == next.SubjectType &&
			existing.Namespace == next.Namespace &&
			existing.Name == next.Name &&
			existing.ValueText == next.ValueText &&
			existing.ValueJSON == next.ValueJSON {
			return claims
		}
	}
	return append(claims, next)
}
