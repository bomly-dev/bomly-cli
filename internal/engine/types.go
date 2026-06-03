package engine

import (
	"io"

	"github.com/bomly-dev/bomly-cli/internal/engine/hooks"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Hook types are re-exported from internal/engine/hooks for existing references
// inside the engine package and as the registry's hook surface. Plugins should depend on
// internal/engine/hooks directly.
type (
	HookDescriptor     = hooks.Descriptor
	PreResolveContext  = hooks.PreResolveContext
	PostResolveContext = hooks.PostResolveContext
	PreResolveHook     = hooks.PreResolveHook
	PostResolveHook    = hooks.PostResolveHook
)

// PipelineRequest defines input for a full pipeline run.
type PipelineRequest struct {
	ProjectPath                string
	ExecutionTarget            sdk.ExecutionTarget
	Subprojects                []sdk.Subproject
	EnrichEnabled              bool
	MatchEnabled               bool
	AuditEnabled               bool
	AnalyzeReachabilityEnabled bool
	ScopeFilter                sdk.Scope
	AuditorFilter              sdk.AuditorFilter
	MatcherFilter              sdk.MatcherFilter
	AnalyzerFilter             sdk.AnalyzerFilter
	DetectorFilter             sdk.DetectorFilter
	FailOn                     []sdk.FailOnConstraint
	FailOnScopes               []sdk.Scope
	AllowVulnerabilityIDs      []string
	AllowLicenses              []string
	DenyLicenses               []string
	LicenseExemptPackages      []string
	DenyPackages               []string
	DenyGroups                 []string
	ProtectedPackages          []string
	TyposquatThreshold         float64
	TyposquatMode              string
	WarnOnly                   bool
	BaselineGraph              *sdk.Graph
	InstallFirst               bool
	InstallArgs                []string
	CoreVersion                string
	Stderr                     io.Writer
	Verbose                    bool
	Progress                   ProgressReporter
}

// ProgressReporter receives coarse pipeline progress events.
type ProgressReporter interface {
	StartStage(label string, total int)
	AdvanceStage(label string, completed, total int)
	CompleteStage(label string, total int)
}

// DetailProgressReporter is optionally implemented by progress renderers that
// can show the current subproject or detector without expanding the public
// coarse progress contract.
type DetailProgressReporter interface {
	Detail(label, detail string)
}

// PipelineWarning is a structured warning captured during a pipeline stage.
type PipelineWarning struct {
	Source  string // detector, auditor, or matcher name
	Message string // human-readable warning text
}

// PipelineResult contains the full output of a pipeline run.
type PipelineResult struct {
	ResolveResults   []sdk.DetectionResult
	Consolidated     sdk.ConsolidatedGraph
	Graph            *sdk.Graph
	Registry         *sdk.PackageRegistry
	Findings         []sdk.Finding
	RiskScores       []sdk.RiskScore
	DetectorWarnings []PipelineWarning
	AuditWarnings    []PipelineWarning
	MatchWarnings    []PipelineWarning
	AnalyzeWarnings  []PipelineWarning
	MatcherRuns      []string
	AuditorRuns      []string
	AnalyzerRuns     []string
	AuditorFindings  map[string]int
	AnalyzerStats    map[string]sdk.ReachabilityStats
	PartialErrors    error
}
