package gping

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// TemplateAppliesTo 定义模板自动匹配的适用范围条件
type TemplateAppliesTo struct {
	Protocol       string   `yaml:"protocol" json:"protocol,omitempty"`
	Ports          []int    `yaml:"ports" json:"ports,omitempty"`
	CurrentService []string `yaml:"current_service" json:"current_service,omitempty"`
	Scheme         []string `yaml:"scheme" json:"scheme,omitempty"`
	SourceTool     []string `yaml:"source_tool" json:"source_tool,omitempty"`
}

// IsZero 判断 AppliesTo 是否为空（没有任何筛选条件）
func (a TemplateAppliesTo) IsZero() bool {
	return strings.TrimSpace(a.Protocol) == "" &&
		len(a.Ports) == 0 &&
		len(a.CurrentService) == 0 &&
		len(a.Scheme) == 0 &&
		len(a.SourceTool) == 0
}

// TemplateVarSpec 定义模板变量的类型、默认值和描述
type TemplateVarSpec struct {
	Type        string `yaml:"type" json:"type,omitempty"`
	Default     string `yaml:"default" json:"default,omitempty"`
	DefaultFrom string `yaml:"default_from" json:"default_from,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Required    bool   `yaml:"required" json:"required,omitempty"`
}

func (s *TemplateVarSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var value string
		if err := node.Decode(&value); err != nil {
			return err
		}
		*s = TemplateVarSpec{Default: value}
		return nil
	case yaml.MappingNode:
		type alias TemplateVarSpec
		var out alias
		if err := node.Decode(&out); err != nil {
			return err
		}
		*s = TemplateVarSpec(out)
		return nil
	default:
		return fmt.Errorf("template var must be a scalar or mapping")
	}
}

// TemplateVars 模板变量的键值对集合
type TemplateVars map[string]TemplateVarSpec

// TemplateExtractSpec 定义从步骤结果中提取字段并映射到 UAM 声明的规则
type TemplateExtractSpec struct {
	From          string `yaml:"from" json:"from,omitempty"`
	Field         string `yaml:"field" json:"field,omitempty"`
	ToClaim       string `yaml:"to_claim" json:"to_claim,omitempty"`
	SubjectType   string `yaml:"subject_type" json:"subject_type,omitempty"`
	Confidence    int    `yaml:"confidence" json:"confidence,omitempty"`
	AssertionMode string `yaml:"assertion_mode" json:"assertion_mode,omitempty"`
}

// TemplateRecommendSpec 定义模板执行后自动生成的资产归类建议
type TemplateRecommendSpec struct {
	VerificationState string            `yaml:"verification_state" json:"verification_state,omitempty"`
	OverrideService   string            `yaml:"override_service_name" json:"override_service_name,omitempty"`
	WhenAll           []string          `yaml:"when_all" json:"when_all,omitempty"`
	Then              map[string]string `yaml:"then" json:"then,omitempty"`
}

// PreviewValues 返回 Recommend 中无条件时的预览值
func (r TemplateRecommendSpec) PreviewValues() map[string]string {
	values := make(map[string]string)
	if len(r.WhenAll) > 0 {
		return values
	}
	if state := strings.TrimSpace(r.VerificationState); state != "" {
		values["verification_state"] = state
	}
	if override := strings.TrimSpace(r.OverrideService); override != "" {
		values["override_service_name"] = override
	}
	for key, value := range r.Then {
		if strings.TrimSpace(value) == "" {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values
}

// ResolvedValues 返回 Recommend 中所有字段的最终取值（含 Then）
func (r TemplateRecommendSpec) ResolvedValues() map[string]string {
	values := make(map[string]string)
	if state := strings.TrimSpace(r.VerificationState); state != "" {
		values["verification_state"] = state
	}
	if override := strings.TrimSpace(r.OverrideService); override != "" {
		values["override_service_name"] = override
	}
	for key, value := range r.Then {
		if strings.TrimSpace(value) == "" {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values
}

// Steps 返回模板的动作列表（优先使用 workflow，否则使用 actions）
func (s TemplateSpec) Steps() []TemplateActionSpec {
	if len(s.Workflow) > 0 {
		return s.Workflow
	}
	return s.Actions
}

func sortedTemplateVarKeys(vars TemplateVars) []string {
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
