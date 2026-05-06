package gping

import (
	"context"
	"fmt"
	"strings"
)

// Preview 对目标执行干运行，返回将要执行的动作预览
func Preview(ctx context.Context, opts Options) (PreviewResult, error) {
	prepared, err := prepareRun(ctx, opts, false)
	if err != nil {
		return PreviewResult{}, err
	}
	return buildPreviewResult(prepared), nil
}

// prepareRun 解析目标、加载模板、规划动作，返回准备好的运行上下文
func prepareRun(ctx context.Context, opts Options, requireActions bool) (preparedRun, error) {
	target, err := ResolveTarget(ctx, opts)
	if err != nil {
		return preparedRun{}, err
	}

	prepared := preparedRun{
		Target:             target,
		SuggestedTemplates: SuggestTemplates(target),
		OperatorAssertions: describeOperatorAssertions(opts),
		WriteUAM:           opts.WriteUAM && strings.TrimSpace(opts.UAMDBPath) != "",
	}

	if strings.TrimSpace(opts.Method) == "" && strings.TrimSpace(opts.TemplateName) == "" {
		if requireActions {
			return preparedRun{}, fmt.Errorf("either --template or --method is required")
		}
		return prepared, nil
	}

	if strings.TrimSpace(opts.TemplateName) != "" {
		spec, err := LoadTemplate(opts.TemplateName)
		if err != nil {
			return preparedRun{}, err
		}
		actions, templateName, err := planFromTemplate(spec, opts, target)
		if err != nil {
			return preparedRun{}, err
		}
		prepared.Template = &spec
		prepared.TemplateName = templateName
		prepared.Actions = actions
		prepared.TemplateSuggest = cloneStringMap(spec.Suggest)
		prepared.TemplateRecommend = spec.Recommend.PreviewValues()
	} else {
		actions, templateName, err := Plan(opts, target)
		if err != nil {
			return preparedRun{}, err
		}
		prepared.TemplateName = templateName
		prepared.Actions = actions
	}
	target = applyActionProtocol(target, prepared.Actions)

	prepared.Target = target
	prepared.SuggestedTemplates = SuggestTemplates(target)
	return prepared, nil
}

func describeOperatorAssertions(opts Options) []string {
	out := make([]string, 0, 2)
	if state := normalizeVerificationState(opts.VerificationState); state != "" {
		out = append(out, "user.verification_state="+state)
	}
	if override := strings.TrimSpace(opts.OverrideService); override != "" {
		out = append(out, "user.override_service_name="+override)
	}
	return out
}
