package engine

import (
	"context"
	"io"

	"github.com/bomly-dev/bomly-cli/internal/engine/hooks"
	model "github.com/bomly-dev/bomly-cli/sdk"
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
	ProjectPath     string
	ExecutionTarget model.ExecutionTarget
	Subprojects     []model.Subproject
	Processor       StageProcessor
	EnrichEnabled   bool
	MatchEnabled    bool
	AuditEnabled    bool
	ScopeFilter     model.Scope
	AuditorFilter   model.AuditorFilter
	MatcherFilter   model.MatcherFilter
	DetectorFilter  model.DetectorFilter
	InstallFirst    bool
	InstallArgs     []string
	CoreVersion     string
	Stderr          io.Writer
	Verbose         bool
	Progress        ProgressReporter
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
	ResolveResults   []model.DetectionResult
	Consolidated     model.ConsolidatedGraph
	Graph            *model.Graph
	Findings         []model.Finding
	RiskScores       []model.RiskScore
	DetectorWarnings []PipelineWarning
	AuditWarnings    []PipelineWarning
	MatchWarnings    []PipelineWarning
	MatcherRuns      []string
	AuditorRuns      []string
	AuditorFindings  map[string]int
	PartialErrors    error
}
