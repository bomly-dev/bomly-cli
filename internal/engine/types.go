package engine

import (
	"io"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// PipelineRequest defines input for a full pipeline run.
type PipelineRequest struct {
	ProjectPath                string
	ExecutionTarget            plugin.ExecutionTarget
	Subprojects                []plugin.Subproject
	EnrichEnabled              bool
	MatchEnabled               bool
	AuditEnabled               bool
	AnalyzeReachabilityEnabled bool
	ScopeFilter                model.Scope
	AuditorFilter              plugin.AuditorFilter
	MatcherFilter              plugin.MatcherFilter
	AnalyzerFilter             plugin.AnalyzerFilter
	DetectorFilter             plugin.DetectorFilter
	FailOn                     []model.FailOnConstraint
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
	DependencyDetailChanges    []model.DependencyDetailTransition
	FindingPolicyResolvers     []model.FindingPolicyResolver
	BaselineEvaluation         *BaselineEvaluation
	BaselineGraph              *model.Graph
	InstallFirst               bool
	InstallArgs                []string
	CoreVersion                string
	Stderr                     io.Writer
	Verbose                    bool
	Progress                   ProgressReporter
}

// BaselineEvaluation identifies the baseline used during policy evaluation.
type BaselineEvaluation struct {
	Path      string
	Entries   int
	Automatic bool
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
	ResolveResults []plugin.DetectionResult
	Consolidated   plugin.ConsolidatedGraph
	Graph          *model.Graph
	Registry       *model.PackageRegistry
	Findings       []model.Finding
	RiskScores     []model.RiskScore
	// DetectorWarnings are every non-fatal detection problem in one list:
	// resolution failures and detector fallbacks the engine observed, plus the
	// package-manager warnings detectors reported alongside their graphs. Each
	// carries a type, so consumers that care only about degraded coverage filter
	// on DetectorWarning.DegradesCoverage rather than on the list being empty.
	DetectorWarnings []plugin.DetectorWarning
	AuditWarnings    []PipelineWarning
	MatchWarnings    []PipelineWarning
	AnalyzeWarnings  []PipelineWarning
	MatcherStats     []plugin.MatcherStats
	AuditorRuns      []string
	AnalyzerRuns     []string
	AuditorFindings  map[string]int
	AnalyzerStats    map[string]plugin.ReachabilityStats
	PartialErrors    error
}
