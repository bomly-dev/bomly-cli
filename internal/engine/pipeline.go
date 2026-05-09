package engine

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/engine/hooks"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Pipeline orchestrates a full scan through a sequence of typed stages:
// pre-resolve hooks -> detect -> scope filter -> consolidate -> match -> audit -> post-resolve hooks.
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

// Run executes the full pipeline and returns a consolidated result.
func (p *Pipeline) Run(ctx context.Context, req PipelineRequest) (PipelineResult, error) {
	result := PipelineResult{}
	if err := p.runPre(ctx, req); err != nil {
		return result, err
	}
	if err := p.runResolve(ctx, &result, req); err != nil {
		return result, err
	}
	if err := p.runScopeFilter(&result, req); err != nil {
		return result, err
	}
	if err := p.runConsolidate(&result, req); err != nil {
		return result, err
	}
	p.runMatch(ctx, &result, req)
	p.runAudit(ctx, &result, req)
	p.runPost(ctx, req, result)
	return result, nil
}

func (p *Pipeline) runPre(ctx context.Context, req PipelineRequest) error {
	if err := hooks.RunPre(ctx, p.Logger, p.Registry.PreResolveHooks(), preHookContext(req)); err != nil {
		return fmt.Errorf("pre-resolve hook: %w", err)
	}
	return nil
}

func (p *Pipeline) runResolve(ctx context.Context, result *PipelineResult, req PipelineRequest) error {
	resolveResults, resolveErr := p.resolveAll(ctx, req)
	result.ResolveResults = resolveResults
	if resolveErr != nil && len(resolveResults) == 0 {
		return fmt.Errorf("dependency resolution: %w", resolveErr)
	}
	if resolveErr != nil {
		result.PartialErrors = resolveErr
		result.DetectorWarnings = PipelineWarningsFromError(resolveErr, "detector")
		p.Logger.Warn("pipeline: partial resolution failures", zap.Error(resolveErr))
	}
	return nil
}

func (p *Pipeline) runScopeFilter(result *PipelineResult, req PipelineRequest) error {
	if req.ScopeFilter == sdk.ScopeUnknown {
		return nil
	}
	filtered, err := filterResultsByScope(result.ResolveResults, req.ScopeFilter)
	if err != nil {
		return fmt.Errorf("scope filter: %w", err)
	}
	result.ResolveResults = filtered
	return nil
}

func (p *Pipeline) runConsolidate(result *PipelineResult, req PipelineRequest) error {
	consolidated, err := consolidation.ConsolidateGraphs(result.ResolveResults)
	if err != nil {
		return fmt.Errorf("consolidation: %w", err)
	}
	result.Consolidated = consolidated

	selectedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		return fmt.Errorf("consolidated graph: %w", err)
	}
	if req.ScopeFilter != sdk.ScopeUnknown {
		selectedGraph, err = FilterGraphByScope(selectedGraph, req.ScopeFilter)
		if err != nil {
			return fmt.Errorf("scope filter consolidated: %w", err)
		}
	}
	result.Graph = selectedGraph
	return nil
}

func (p *Pipeline) runMatch(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if (!req.EnrichEnabled && !req.MatchEnabled) || result.Graph == nil {
		return
	}
	if req.Progress != nil {
		req.Progress.StartStage("Enriching packages", 1)
	}
	p.match(ctx, result, req)
	if req.Progress != nil {
		req.Progress.CompleteStage("Enriching packages", 1)
	}
}

func (p *Pipeline) runAudit(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if !req.AuditEnabled || result.Graph == nil {
		return
	}
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
	result.Findings = DeduplicateFindings(auditResult.Findings)
	result.RiskScores = auditResult.RiskScores
	result.AuditorRuns = auditResult.AuditorRuns
	result.AuditorFindings = auditResult.AuditorFindings
	result.AuditWarnings = append(result.AuditWarnings, auditWarnings...)
	if req.Progress != nil {
		req.Progress.CompleteStage("Evaluating policy", 1)
	}
}

func (p *Pipeline) runPost(ctx context.Context, req PipelineRequest, result PipelineResult) {
	if err := hooks.RunPost(ctx, p.Logger, p.Registry.PostResolveHooks(), postHookContext(req, result)); err != nil {
		p.Logger.Warn("pipeline: post-resolve hook error", zap.Error(err))
	}
}

func preHookContext(req PipelineRequest) hooks.PreResolveContext {
	return hooks.PreResolveContext{
		ExecutionTarget: req.ExecutionTarget,
		Subprojects:     req.Subprojects,
		ProjectPath:     req.ProjectPath,
		Stderr:          req.Stderr,
	}
}

func postHookContext(req PipelineRequest, result PipelineResult) hooks.PostResolveContext {
	return hooks.PostResolveContext{
		Consolidated: result.Consolidated,
		Findings:     result.Findings,
		ProjectPath:  req.ProjectPath,
		Stderr:       req.Stderr,
	}
}

func (p *Pipeline) match(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if result.Graph == nil {
		return
	}
	mReq := sdk.MatchRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeFullGraph,
		Graph:           result.Graph,
		MatcherFilter:   req.MatcherFilter,
		Stderr:          req.Stderr,
	}
	matchResult, err := p.engine.Match(ctx, mReq)
	result.MatcherRuns = matchResult.MatcherRuns
	if matchResult.Graph != nil {
		result.Graph = matchResult.Graph
		consolidation.SyncConsolidatedEnrichmentToManifests(&result.Consolidated, matchResult.Graph)
	}
	if err != nil {
		result.MatchWarnings = PipelineWarningsFromError(err, "matcher")
		p.Logger.Warn("pipeline: matcher enrichment error", zap.Error(err))
	}
}

func (p *Pipeline) audit(ctx context.Context, g *sdk.Graph, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	auditReq := sdk.AuditRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeFullGraph,
		Graph:           g,
		AuditorFilter:   req.AuditorFilter,
		Stderr:          req.Stderr,
	}
	result, err := p.engine.Audit(ctx, auditReq)
	var warnings []PipelineWarning
	if err != nil {
		warnings = PipelineWarningsFromError(err, "auditor")
		p.Logger.Warn("pipeline: audit errors", zap.Error(err))
	}
	return result, warnings
}

func (p *Pipeline) auditComponent(ctx context.Context, g *sdk.Graph, target *sdk.Package, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	if g == nil || target == nil {
		return sdk.AuditResult{}, nil
	}
	auditReq := sdk.AuditRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeComponent,
		Graph:           g,
		Target:          target,
		Ecosystem:       sdk.Ecosystem(target.Ecosystem),
		AuditorFilter:   req.AuditorFilter,
		Stderr:          req.Stderr,
	}
	result, err := p.engine.Audit(ctx, auditReq)
	result.Findings = DeduplicateFindings(result.Findings)
	var warnings []PipelineWarning
	if err != nil {
		warnings = PipelineWarningsFromError(err, "auditor")
		p.Logger.Warn("pipeline: component audit errors", zap.Error(err))
	}
	return result, warnings
}
