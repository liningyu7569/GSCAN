package gping

import (
	"Going_Scan/internal/uam/normalize"
	"time"
)

// Options 汇集 gping 命令行参数与运行选项
type Options struct {
	Commandline string

	URL          string
	IP           string
	Port         int
	Protocol     string
	Route        string
	Method       string
	TemplateName string
	UAMDBPath    string
	UAMEndpoint  string
	UAMService   string
	UAMVerify    string
	PickFirst    bool
	PickIndex    int

	HostHeader string
	SNI        string
	Path       string
	Body       string
	Payload    string
	PayloadHex string
	ReadBytes  int
	Headers    map[string]string
	Vars       map[string]string
	Retries    int
	TTL        int
	TOS        int
	IPID       int
	DF         bool
	BadSum     bool
	SourcePort int
	TCPFlags   string
	TCPSeq     int64
	TCPAck     int64
	TCPWindow  int
	ICMPID     int
	ICMPSeq    int
	ICMPType   int
	ICMPCode   int

	InsecureSkipVerify bool
	WriteUAM           bool
	OutputJSON         bool
	VerificationState  string
	OverrideService    string
	Timeout            time.Duration
}

// TargetContext 统一的目标上下文，存储解析后的 IP、端口、协议、URL 及 UAM 已有元数据
type TargetContext struct {
	IP                string `json:"ip"`
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"`
	Scheme            string `json:"scheme,omitempty"`
	Host              string `json:"host,omitempty"`
	HostHeader        string `json:"host_header,omitempty"`
	SNI               string `json:"sni,omitempty"`
	URL               string `json:"url,omitempty"`
	Path              string `json:"path,omitempty"`
	Source            string `json:"source"`
	UAMEndpointID     string `json:"uam_endpoint_id,omitempty"`
	CurrentService    string `json:"current_service,omitempty"`
	CurrentProduct    string `json:"current_product,omitempty"`
	CurrentVersion    string `json:"current_version,omitempty"`
	CurrentBanner     string `json:"current_banner,omitempty"`
	VerificationState string `json:"verification_state,omitempty"`
}

// ActionUnit 单个探测动作，包含路由、方法、参数、条件及容错配置
type ActionUnit struct {
	Index              int               `json:"index"`
	ID                 string            `json:"id,omitempty"`
	Name               string            `json:"name,omitempty"`
	Route              string            `json:"route"`
	Adapter            string            `json:"adapter,omitempty"`
	Method             string            `json:"method"`
	URL                string            `json:"url,omitempty"`
	HostHeader         string            `json:"host_header,omitempty"`
	SNI                string            `json:"sni,omitempty"`
	Path               string            `json:"path,omitempty"`
	Body               string            `json:"body,omitempty"`
	Payload            string            `json:"payload,omitempty"`
	ReadBytes          int               `json:"read_bytes,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Params             map[string]any    `json:"params,omitempty"`
	When               string            `json:"when,omitempty"`
	ContinueOnError    bool              `json:"continue_on_error,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	Timeout            time.Duration     `json:"timeout,omitempty"`
}

// ExecutionReport 单步执行报告，记录路由方法、原始状态、请求/响应摘要及推断的 UAM 断言
type ExecutionReport struct {
	IP              string                      `json:"ip"`
	Protocol        string                      `json:"protocol"`
	Port            int                         `json:"port"`
	StepID          string                      `json:"step_id,omitempty"`
	RouteUsed       string                      `json:"route_used"`
	ActionType      string                      `json:"action_type"`
	RawMethod       string                      `json:"raw_method"`
	RawStatus       string                      `json:"raw_status"`
	RequestSummary  string                      `json:"request_summary,omitempty"`
	ResponseSummary string                      `json:"response_summary,omitempty"`
	RTTMs           *float64                    `json:"rtt_ms,omitempty"`
	ErrorText       string                      `json:"error_text,omitempty"`
	ExtraJSON       string                      `json:"extra_json,omitempty"`
	Claims          []normalize.GPingClaimInput `json:"claims,omitempty"`
}

// RunResult 单次 gping 运行的完整结果
type RunResult struct {
	Target          TargetContext     `json:"target"`
	TemplateName    string            `json:"template_name,omitempty"`
	Actions         []ActionUnit      `json:"actions"`
	Reports         []ExecutionReport `json:"reports"`
	Recommendations []Recommendation  `json:"recommendations,omitempty"`
	UAMRunID        string            `json:"uam_run_id,omitempty"`
}

// TemplateSpec 探测模板定义，描述适用条件、变量、动作流程、提取规则和建议
type TemplateSpec struct {
	Kind        string                `yaml:"kind" json:"kind,omitempty"`
	Name        string                `yaml:"name" json:"name"`
	Description string                `yaml:"description" json:"description,omitempty"`
	AppliesTo   TemplateAppliesTo     `yaml:"applies_to" json:"applies_to,omitempty"`
	Vars        TemplateVars          `yaml:"vars" json:"vars,omitempty"`
	Workflow    []TemplateActionSpec  `yaml:"workflow" json:"workflow,omitempty"`
	Actions     []TemplateActionSpec  `yaml:"actions" json:"actions,omitempty"`
	Extract     []TemplateExtractSpec `yaml:"extract" json:"extract,omitempty"`
	Recommend   TemplateRecommendSpec `yaml:"recommend" json:"recommend,omitempty"`
	Suggest     map[string]string     `yaml:"suggest" json:"suggest,omitempty"`
}

// TemplateActionSpec 模板中的单个动作定义，支持变量展开
type TemplateActionSpec struct {
	ID                 string            `yaml:"id" json:"id,omitempty"`
	Name               string            `yaml:"name"`
	Route              string            `yaml:"route"`
	Adapter            string            `yaml:"adapter" json:"adapter,omitempty"`
	Method             string            `yaml:"method"`
	URL                string            `yaml:"url"`
	HostHeader         string            `yaml:"host_header"`
	SNI                string            `yaml:"sni"`
	Path               string            `yaml:"path"`
	Body               string            `yaml:"body"`
	Payload            string            `yaml:"payload"`
	ReadBytes          int               `yaml:"read_bytes"`
	Headers            map[string]string `yaml:"headers"`
	Params             map[string]any    `yaml:"params" json:"params,omitempty"`
	When               string            `yaml:"when" json:"when,omitempty"`
	ContinueOnError    bool              `yaml:"continue_on_error" json:"continue_on_error,omitempty"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify"`
}

// TemplateSummary 模板摘要，用于列表展示
type TemplateSummary struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ActionCount int      `json:"action_count"`
	Routes      []string `json:"routes,omitempty"`
}

// Candidate 来自 UAM 的探测候选端点
type Candidate struct {
	EndpointID         string   `json:"endpoint_id"`
	IP                 string   `json:"ip"`
	Protocol           string   `json:"protocol"`
	Port               int      `json:"port"`
	CurrentService     string   `json:"current_service,omitempty"`
	VerificationState  string   `json:"verification_state"`
	LastSeenAt         string   `json:"last_seen_at,omitempty"`
	SourceTool         string   `json:"source_tool,omitempty"`
	CurrentProduct     string   `json:"current_product,omitempty"`
	CurrentVersion     string   `json:"current_version,omitempty"`
	CurrentBanner      string   `json:"current_banner,omitempty"`
	SuggestedTemplates []string `json:"suggested_templates,omitempty"`
}

// PreviewResult 探测预览结果，展示目标、动作和推荐信息
type PreviewResult struct {
	Target             TargetContext     `json:"target"`
	TemplateName       string            `json:"template_name,omitempty"`
	Actions            []ActionUnit      `json:"actions,omitempty"`
	SuggestedTemplates []string          `json:"suggested_templates,omitempty"`
	TemplateSuggest    map[string]string `json:"template_suggest,omitempty"`
	TemplateRecommend  map[string]string `json:"template_recommend,omitempty"`
	OperatorAssertions []string          `json:"operator_assertions,omitempty"`
	WriteUAM           bool              `json:"write_uam"`
}

// routeEvidence 路由证据的内部表示，承载原始状态、响应详情、TLS 信息等
type routeEvidence struct {
	RawStatus       string
	RequestSummary  string
	ResponseSummary string
	RTTMs           *float64
	ErrorText       string
	Fields          map[string]any
	Extra           map[string]any
	StatusCode      int
	Server          string
	Location        string
	Title           string
	BodyPreview     string
	Banner          string
	Product         string
	Version         string
	TLSSubject      string
	TLSIssuer       string
	TLSSANs         []string
	TLSALPN         string
	TLSVersion      string
}

// Recommendation 基于模板推断的操作建议（验证状态、服务覆写）
type Recommendation struct {
	VerificationState string `json:"verification_state,omitempty"`
	OverrideService   string `json:"override_service_name,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

func supportedMethods() map[string]string {
	return map[string]string{
		"tcp-syn":                "raw",
		"tcp-raw":                "raw",
		"icmp-echo-raw":          "raw",
		"icmp-raw":               "raw",
		"tcp-connect":            "stack",
		"banner-read":            "stack",
		"tls-handshake":          "stack",
		"http-head":              "app",
		"http-get":               "app",
		"http-post":              "app",
		"dns-query":              "app",
		"ftp-banner":             "app",
		"ftp-feat":               "app",
		"ftp-auth-tls":           "app",
		"smtp-banner":            "app",
		"smtp-ehlo":              "app",
		"smtp-starttls":          "app",
		"redis-ping":             "app",
		"redis-info-server":      "app",
		"redis-info-replication": "app",
		"ssh-banner":             "app",
		"ssh-kexinit":            "app",
		"ssh-hostkey":            "app",
		"mysql-greeting":         "app",
		"mysql-capabilities":     "app",
		"mysql-starttls":         "app",
	}
}
