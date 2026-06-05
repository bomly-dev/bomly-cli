package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/engine/hooks"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Pipeline orchestrates a full scan through a sequence of typed stages:
// pre-resolve hooks -> detect -> consolidate -> match -> analyze -> audit -> post-resolve hooks.
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
	result, err := p.RunPreAudit(ctx, req)
	if err != nil {
		return result, err
	}
	p.runAudit(ctx, &result, req)
	p.runPost(ctx, req, result)
	return result, nil
}

// RunPreAudit executes the pipeline through enrichment and analysis, stopping
// before policy evaluation and post-resolve hooks.
func (p *Pipeline) RunPreAudit(ctx context.Context, req PipelineRequest) (PipelineResult, error) {
	result := PipelineResult{}
	if err := p.runPre(ctx, req); err != nil {
		return result, err
	}
	if err := p.runResolve(ctx, &result, req); err != nil {
		return result, err
	}
	if err := p.runConsolidate(&result, req); err != nil {
		return result, err
	}
	p.runMatch(ctx, &result, req)
	p.runAnalyze(ctx, &result, req)
	return result, nil
}

// RunAuditGraph evaluates policy for graph using req's configured auditors.
func (p *Pipeline) RunAuditGraph(ctx context.Context, graph *sdk.Graph, registry *sdk.PackageRegistry, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	if !req.AuditEnabled || graph == nil {
		return sdk.AuditResult{}, nil
	}
	if req.Progress != nil {
		req.Progress.StartStage("Evaluating policy", 1)
	}
	auditResult, auditWarnings := p.audit(ctx, graph, registry, req)
	auditResult.Findings = DeduplicateFindings(auditResult.Findings)
	if req.WarnOnly {
		for idx := range auditResult.Findings {
			if auditResult.Findings[idx].Disposition == "" || auditResult.Findings[idx].Disposition == sdk.FindingDispositionFail {
				auditResult.Findings[idx].Disposition = sdk.FindingDispositionWarn
			}
		}
	}
	if req.Progress != nil {
		req.Progress.CompleteStage("Evaluating policy", 1)
	}
	return auditResult, auditWarnings
}

// RunPostResolveHooks executes post-resolve hooks with the supplied result.
func (p *Pipeline) RunPostResolveHooks(ctx context.Context, req PipelineRequest, result PipelineResult) {
	p.runPost(ctx, req, result)
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
	p.logUnexpectedMultiRootResolveGraphs(resolveResults)
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
	result.Graph = selectedGraph
	result.Registry = consolidation.BuildPackageRegistry(consolidated)
	p.logUnexpectedMultiRootGraph("consolidated", "", "", selectedGraph, sdk.ManifestMetadata{})
	return nil
}

func (p *Pipeline) logUnexpectedMultiRootResolveGraphs(results []sdk.DetectionResult) {
	for _, result := range results {
		if result.Graphs == nil {
			continue
		}
		for _, entry := range result.Graphs.Entries {
			p.logUnexpectedMultiRootGraph(
				"resolve",
				result.DetectorName,
				result.SubprojectInfo.RelativePath,
				entry.Graph,
				entry.Manifest,
			)
		}
	}
}

func (p *Pipeline) logUnexpectedMultiRootGraph(stage, detector, subproject string, graph *sdk.Graph, manifest sdk.ManifestMetadata) {
	if p == nil || p.Logger == nil || graph == nil {
		return
	}
	roots := graph.Roots()
	if len(roots) <= 1 {
		return
	}
	hasApplicationRoot := false
	rootIDs := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == nil {
			continue
		}
		rootIDs = append(rootIDs, root.ID)
		if strings.EqualFold(strings.TrimSpace(root.Type), "application") {
			hasApplicationRoot = true
		}
	}
	if !hasApplicationRoot {
		return
	}
	p.Logger.Warn(
		"pipeline: unexpected multi-root graph detected",
		zap.String("stage", stage),
		zap.String("detector", detector),
		zap.String("subproject", subproject),
		zap.String("manifest_path", strings.TrimSpace(manifest.Path)),
		zap.Int("root_count", len(roots)),
		zap.Strings("root_ids", rootIDs),
	)
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

// runAnalyze runs the reachability analyzer stage when --reachability is
// set. Errors degrade to warnings; analyzer failure must never abort the
// pipeline.
func (p *Pipeline) runAnalyze(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if !req.AnalyzeReachabilityEnabled || result.Graph == nil {
		return
	}
	if req.Progress != nil {
		req.Progress.StartStage("Analyzing reachability", 1)
	}
	p.analyze(ctx, result, req)
	if req.Progress != nil {
		req.Progress.CompleteStage("Analyzing reachability", 1)
	}
}

func (p *Pipeline) analyze(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if result.Graph == nil {
		return
	}
	aReq := sdk.AnalyzeRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeFullGraph,
		Graph:           result.Graph,
		Registry:        result.Registry,
		AnalyzerFilter:  req.AnalyzerFilter,
		Stderr:          req.Stderr,
	}
	analyzeResult, err := p.engine.Analyze(ctx, aReq)
	result.AnalyzerRuns = analyzeResult.AnalyzerRuns
	if len(analyzeResult.AnalyzerStats) > 0 {
		result.AnalyzerStats = analyzeResult.AnalyzerStats
	}
	if analyzeResult.Registry != nil {
		result.Registry = analyzeResult.Registry
	}
	if err != nil {
		result.AnalyzeWarnings = PipelineWarningsFromError(err, "analyzer")
		p.Logger.Warn("pipeline: reachability analysis errors", zap.Error(err))
	}
}

func (p *Pipeline) runAudit(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if !req.AuditEnabled || result.Graph == nil {
		return
	}
	if req.Progress != nil {
		req.Progress.StartStage("Evaluating policy", 1)
	}
	if !RegistryHasVulnerabilityData(result.Registry) {
		result.AuditWarnings = append(result.AuditWarnings, PipelineWarning{
			Source:  "vulnerability",
			Message: "no vulnerability enrichment input was available; policy evaluation may produce no findings",
		})
	}
	auditResult, auditWarnings := p.audit(ctx, result.Graph, result.Registry, req)
	result.Findings = DeduplicateFindings(auditResult.Findings)
	if req.WarnOnly {
		for idx := range result.Findings {
			if result.Findings[idx].Disposition == "" || result.Findings[idx].Disposition == sdk.FindingDispositionFail {
				result.Findings[idx].Disposition = sdk.FindingDispositionWarn
			}
		}
	}
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
		Registry:        result.Registry,
		MatcherFilter:   req.MatcherFilter,
		Stderr:          req.Stderr,
	}
	matchResult, err := p.engine.Match(ctx, mReq)
	result.MatcherRuns = matchResult.MatcherRuns
	if matchResult.Registry != nil {
		result.Registry = matchResult.Registry
	}
	if err != nil {
		result.MatchWarnings = PipelineWarningsFromError(err, "matcher")
		p.Logger.Warn("pipeline: matcher enrichment error", zap.Error(err))
	}
}

func (p *Pipeline) audit(ctx context.Context, g *sdk.Graph, registry *sdk.PackageRegistry, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	auditReq := sdk.AuditRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeFullGraph,
		Graph:           g,
		Registry:        registry,
		BaselineGraph:   req.BaselineGraph,
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

func (p *Pipeline) auditComponent(ctx context.Context, g *sdk.Graph, registry *sdk.PackageRegistry, target *sdk.Dependency, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	if g == nil || target == nil {
		return sdk.AuditResult{}, nil
	}
	auditReq := sdk.AuditRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            sdk.TargetModeComponent,
		Graph:           g,
		Registry:        registry,
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
