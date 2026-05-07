package engine

import (
	"context"
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

// StageProcessor is a command-specific graph manipulation step injected into the
// pipeline between consolidation and audit. Return a non-nil error to abort.
type StageProcessor func(context.Context, *PipelineResult) error

// PipelineRequest defines input for a full pipeline run.
type PipelineRequest struct {
	ProjectPath                string
	ExecutionTarget            sdk.ExecutionTarget
	Subprojects                []sdk.Subproject
	Processor                  StageProcessor
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
