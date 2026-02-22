package scan

import (
	"context"
	"io"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// ---------------------------------------------------------------------------
// Hook interfaces
// ---------------------------------------------------------------------------

// HookDescriptor describes a hook registration.
type HookDescriptor struct {
	Name     string
	Priority int
	Stage    string // "pre-resolve" | "post-resolve"
}

// PreResolveContext provides inputs available before detection.
type PreResolveContext struct {
	ExecutionTarget model.ExecutionTarget
	Subprojects     []model.Subproject
	ProjectPath     string
	Stderr          io.Writer
}

// PostResolveContext provides inputs available after full resolution.
type PostResolveContext struct {
	Consolidated model.ConsolidatedGraph
	Findings     []model.Finding
	ProjectPath  string
	Stderr       io.Writer
}

// PreResolveHook runs logic before detection.
type PreResolveHook interface {
	Descriptor() HookDescriptor
	Execute(context.Context, PreResolveContext) error
}

// PostResolveHook runs logic after all resolutions and auditing.
type PostResolveHook interface {
	Descriptor() HookDescriptor
	Execute(context.Context, PostResolveContext) error
}

// ---------------------------------------------------------------------------
// Pipeline types
// ---------------------------------------------------------------------------

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
