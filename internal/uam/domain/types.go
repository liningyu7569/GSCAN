package domain

import (
	"fmt"
	"strings"
	"time"
)

const (
	ToolGS     = "gs"
	ToolGPing  = "gping"
	ToolModule = "module"
)

const (
	ModuleNameGS = "gs-l4l7"
)

const (
	SubjectHost     = "host"
	SubjectEndpoint = "endpoint"
)

const (
	RouteStack = "stack"
	RouteRaw   = "raw"
	RouteApp   = "app"
)

const (
	ActionReach     = "reach"
	ActionProbe     = "probe"
	ActionHandshake = "handshake"
	ActionRequest   = "request"
	ActionInject    = "inject"
	ActionScan      = "scan"
	ActionCollect   = "collect"
)

const (
	AssertionObserved = "observed"
	AssertionInferred = "inferred"
	AssertionManual   = "manual"
	AssertionOverride = "override"
)

const (
	VerificationNone       = "none"
	VerificationPending    = "pending"
	VerificationConfirmed  = "confirmed"
	VerificationOverridden = "overridden"
)

const (
	HostReachable   = "reachable"
	HostUnreachable = "unreachable"
	HostUnknown     = "unknown"
)

const (
	PortStateOpen       = "open"
	PortStateClosed     = "closed"
	PortStateFiltered   = "filtered"
	PortStateUnfiltered = "unfiltered"
	PortStateLikelyOpen = "likely_open"
	PortStateUnknown    = "unknown"
)

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

type Host struct {
	HostID      string
	IP          string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type Endpoint struct {
	EndpointID  string
	HostID      string
	Protocol    string
	Port        int
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

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

func HostIDFromIP(ip string) string {
	return "host:" + ip
}

func EndpointID(hostID string, protocol string, port int) string {
	return fmt.Sprintf("%s:%s:%d", hostID, strings.ToLower(protocol), port)
}
