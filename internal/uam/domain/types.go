package domain

import (
	"fmt"
	"strings"
	"time"
)

// 工具类型常量
const (
	ToolGS     = "gs"
	ToolGPing  = "gping"
	ToolModule = "module"
)

// 模块名称常量
const (
	ModuleNameGS = "gs-l4l7"
)

// 主体类型常量
const (
	SubjectHost     = "host"
	SubjectEndpoint = "endpoint"
)

// 路由类型常量
const (
	RouteStack = "stack"
	RouteRaw   = "raw"
	RouteApp   = "app"
)

// 动作类型常量
const (
	ActionReach     = "reach"
	ActionProbe     = "probe"
	ActionHandshake = "handshake"
	ActionRequest   = "request"
	ActionInject    = "inject"
	ActionScan      = "scan"
	ActionCollect   = "collect"
)

// 断言模式常量
const (
	AssertionObserved = "observed"
	AssertionInferred = "inferred"
	AssertionManual   = "manual"
	AssertionOverride = "override"
)

// 验证状态常量
const (
	VerificationNone       = "none"
	VerificationPending    = "pending"
	VerificationConfirmed  = "confirmed"
	VerificationOverridden = "overridden"
)

// 主机可达性常量
const (
	HostReachable   = "reachable"
	HostUnreachable = "unreachable"
	HostUnknown     = "unknown"
)

// 端口状态常量
const (
	PortStateOpen       = "open"
	PortStateClosed     = "closed"
	PortStateFiltered   = "filtered"
	PortStateUnfiltered = "unfiltered"
	PortStateLikelyOpen = "likely_open"
	PortStateUnknown    = "unknown"
)

// Run 一次扫描运行记录，关联到某个工具的某次执行
type Run struct {
	RunID        string
	Tool         string
	ModuleName   string
	Commandline  string
	StartedAt    time.Time
	FinishedAt   *time.Time
	TargetsJSON  string
	ProfilesJSON string
	PortsJSON    string
	ServiceScan  bool
	ExtraJSON    string
}

// Host 主机资产对象，以IP为唯一标识
type Host struct {
	HostID      string
	IP          string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// Endpoint 端点资产对象，由主机+协议+端口三元组唯一标识
type Endpoint struct {
	EndpointID  string
	HostID      string
	Protocol    string
	Port        int
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// Observation 一次探测观察的原始记录，属于某个Run，落在某个Host/Endpoint上
type Observation struct {
	ObservationID   string
	RunID           string
	Tool            string
	ModuleName      string
	HostID          string
	EndpointID      *string
	RouteUsed       *string
	ActionType      string
	RawMethod       string
	RawStatus       string
	RequestSummary  string
	ResponseSummary string
	RTTMs           *float64
	ErrorText       string
	ObservedAt      time.Time
	ExtraJSON       string
}

// Claim 一条断言声明，由Observation推导而来，声明某个Subject的某个属性取值
type Claim struct {
	ClaimID       string
	ObservationID string
	SubjectType   string
	SubjectID     string
	Namespace     string
	Name          string
	ValueText     *string
	ValueJSON     *string
	Confidence    int
	AssertionMode string
	ClaimedAt     time.Time
}

// HostProjectionCurrent 主机级当前投影，聚合多轮Claim后的最新主机状态快照
type HostProjectionCurrent struct {
	HostID                 string
	CurrentReachability    *string
	ReachabilityConfidence *int
	VerificationState      string
	LastSeenAt             *time.Time
	LastClaimID            *string
	LastObservationID      *string
	SourceTool             *string
}

// EndpointProjectionCurrent 端口级当前投影，聚合多轮Claim后的最新端口状态快照
type EndpointProjectionCurrent struct {
	EndpointID          string
	CurrentPortState    *string
	PortStateConfidence *int
	CurrentService      *string
	CurrentProduct      *string
	CurrentVersion      *string
	CurrentInfo         *string
	CurrentHostname     *string
	CurrentOS           *string
	CurrentDevice       *string
	CurrentBanner       *string
	CurrentCPEsJSON     *string
	VerificationState   string
	LastSeenAt          *time.Time
	LastClaimID         *string
	LastObservationID   *string
	SourceTool          *string
}

// ModuleResult 模块执行的结构化产出，关联到某次Observation
type ModuleResult struct {
	ModuleResultID string
	RunID          string
	ObservationID  *string
	SubjectType    string
	SubjectID      string
	ModuleName     string
	SchemaVersion  string
	DataJSON       string
	CreatedAt      time.Time
}

// HostIDFromIP 将IP转换为HostID
func HostIDFromIP(ip string) string {
	return "host:" + ip
}

// EndpointID 根据hostID、协议和端口生成EndpointID
func EndpointID(hostID string, protocol string, port int) string {
	return fmt.Sprintf("%s:%s:%d", hostID, strings.ToLower(protocol), port)
}
