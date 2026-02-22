package scan

import (
	"context"
	"fmt"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Pipeline orchestrates a full scan through a sequence of typed stages:
// pre-resolve hooks → detect → consolidate → match → process → audit → post-resolve hooks.
type Pipeline struct {
	Registry *Registry
	Logger   *zap.Logger
	engine   *Engine
}

// NewPipeline creates a pipeline backed by the given registry.
func NewPipeline(registry *Registry, logger *zap.Logger) *Pipeline {
	if registry == nil {
		registry = NewRegistry(RegistryConfigs{}, *zap.NewNop())
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Pipeline{
		Registry: registry,
		Logger:   logger,
		engine:   NewEngine(registry),
	}
}

// ResolveAll runs pre-hooks and the resolution stage (with ecosystem chain
// support), returning raw per-subproject results. This is useful for commands
// that need per-result processing before consolidation (e.g., explain, diff).
func (p *Pipeline) ResolveAll(ctx context.Context, req PipelineRequest) ([]model.DetectionResult, error) {
	if err := p.runPreHooks(ctx, req); err != nil {
		return nil, fmt.Errorf("pre-resolve hook: %w", err)
	}
	return p.resolveAll(ctx, req)
}

// Run executes the full pipeline and returns a consolidated result.
func (p *Pipeline) Run(ctx context.Context, req PipelineRequest) (PipelineResult, error) {
	result := PipelineResult{}

	// 1. Pre-resolve hooks.
	if err := p.runPreHooks(ctx, req); err != nil {
		return result, fmt.Errorf("pre-resolve hook: %w", err)
	}

	// 2. Detect — resolve dependency graphs for each subproject.
	resolveResults, resolveErr := p.resolveAll(ctx, req)
	result.ResolveResults = resolveResults
	if resolveErr != nil && len(resolveResults) == 0 {
		return result, fmt.Errorf("dependency resolution: %w", resolveErr)
	}
	if resolveErr != nil {
		result.PartialErrors = resolveErr
		result.DetectorWarnings = PipelineWarningsFromError(resolveErr, "detector")
		p.Logger.Warn("pipeline: partial resolution failures", zap.Error(resolveErr))
	}

	// 3. Scope-filter resolve results.
	if req.ScopeFilter != model.ScopeUnknown {
		filtered, err := filterResultsByScope(resolveResults, req.ScopeFilter)
		if err != nil {
			return result, fmt.Errorf("scope filter: %w", err)
		}
		result.ResolveResults = filtered
		resolveResults = filtered
	}

	// 4. Consolidate graphs.
	consolidated, err := ConsolidateGraphs(resolveResults)
	if err != nil {
		return result, fmt.Errorf("consolidation: %w", err)
	}
	result.Consolidated = consolidated

	selectedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		return result, fmt.Errorf("consolidated graph: %w", err)
	}
	if req.ScopeFilter != model.ScopeUnknown {
		selectedGraph, err = FilterGraphByScope(selectedGraph, req.ScopeFilter)
		if err != nil {
			return result, fmt.Errorf("scope filter consolidated: %w", err)
		}
	}
	result.Graph = selectedGraph

	// 5. Matcher enrichment (on consolidated graph to avoid duplicate calls).
	if (req.EnrichEnabled || req.MatchEnabled) && result.Graph != nil {
		if req.Progress != nil {
			req.Progress.StartStage("Enriching packages", 1)
		}
		p.match(ctx, &result, req)
		if req.Progress != nil {
			req.Progress.CompleteStage("Enriching packages", 1)
		}
	}

	// 6. Command-specific processing.
	if req.Processor != nil {
		if err := req.Processor(ctx, &result); err != nil {
			return result, fmt.Errorf("stage processor: %w", err)
		}
	}

	// 7. Audit.
	if req.AuditEnabled && result.Graph != nil {
		if req.Progress != nil {
			req.Progress.StartStage("Evaluating policy", 1)
		}
		if !GraphHasVulnerabilityData(result.Graph) {
			result.AuditWarnings = append(result.AuditWarnings, PipelineWarning{
				Source:  "severity-policy",
				Message: "no vulnerability enrichment input was available; policy evaluation may produce no findings",
			})
		}
		auditResult, auditWarnings := p.audit(ctx, result.Graph, req)
		result.Findings = auditResult.Findings
		result.RiskScores = auditResult.RiskScores
		result.AuditorRuns = auditResult.AuditorRuns
		result.AuditorFindings = auditResult.AuditorFindings
		result.AuditWarnings = append(result.AuditWarnings, auditWarnings...)
		if req.Progress != nil {
			req.Progress.CompleteStage("Evaluating policy", 1)
		}
	}

	// 8. Post-resolve hooks.
	if err := p.runPostHooks(ctx, req, result); err != nil {
		p.Logger.Warn("pipeline: post-resolve hook error", zap.Error(err))
	}

	return result, nil
}

func (p *Pipeline) match(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if result.Graph == nil {
		return
	}
	mReq := model.MatchRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            model.TargetModeFullGraph,
		Graph:           result.Graph,
		MatcherFilter:   req.MatcherFilter,
		Stderr:          req.Stderr,
	}
	matchResult, err := p.engine.Match(ctx, mReq)
	result.MatcherRuns = matchResult.MatcherRuns
	if matchResult.Graph != nil {
		result.Graph = matchResult.Graph
		SyncConsolidatedEnrichmentToManifests(&result.Consolidated, matchResult.Graph)
	}
	if err != nil {
		result.MatchWarnings = PipelineWarningsFromError(err, "matcher")
		p.Logger.Warn("pipeline: matcher enrichment error", zap.Error(err))
	}
}

func (p *Pipeline) audit(ctx context.Context, g *model.Graph, req PipelineRequest) (model.AuditResult, []PipelineWarning) {
	auditReq := model.AuditRequest{
		ProjectPath:   req.ProjectPath,
		Mode:          model.TargetModeFullGraph,
		Graph:         g,
		AuditorFilter: req.AuditorFilter,
		Stderr:        req.Stderr,
	}
	result, err := p.engine.Audit(ctx, auditReq)
	var warnings []PipelineWarning
	if err != nil {
		warnings = PipelineWarningsFromError(err, "auditor")
		p.Logger.Warn("pipeline: audit errors", zap.Error(err))
	}
	return result, warnings
}
