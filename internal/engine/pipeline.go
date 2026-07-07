package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Pipeline orchestrates a full scan through a sequence of typed stages:
// detect (resolve + consolidate) -> match -> analyze -> audit.
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
	return result, nil
}

// RunPreAudit executes the pipeline through enrichment and analysis, stopping
// before policy evaluation.
func (p *Pipeline) RunPreAudit(ctx context.Context, req PipelineRequest) (PipelineResult, error) {
	result := PipelineResult{}
	if err := p.runDetect(ctx, &result, req); err != nil {
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
	return p.runAuditStage(ctx, graph, registry, req)
}

// runAuditStage evaluates policy for graph, applying finding deduplication,
// warn-only disposition rewriting, stage progress, and Info-level
// start/completion logging. Shared by RunAuditGraph (explain's component
// audit path) and runAudit (the full-scan audit stage) so the two callers
// cannot drift out of sync.
func (p *Pipeline) runAuditStage(ctx context.Context, graph *sdk.Graph, registry *sdk.PackageRegistry, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	if req.Progress != nil {
		req.Progress.StartStage("Evaluating policy", 1)
	}
	started := time.Now()
	p.Logger.Info("pipeline: policy evaluation started", zap.Int("packages", graph.Size()))
	auditResult, auditWarnings := p.audit(ctx, graph, registry, req)
	auditResult.Findings = DeduplicateFindings(auditResult.Findings)
	if req.WarnOnly {
		for idx := range auditResult.Findings {
			if auditResult.Findings[idx].Disposition == "" || auditResult.Findings[idx].Disposition == sdk.FindingDispositionFail {
				auditResult.Findings[idx].Disposition = sdk.FindingDispositionWarn
			}
		}
	}
	p.Logger.Info("pipeline: policy evaluation completed",
		zap.Strings("auditor_runs", auditResult.AuditorRuns),
		zap.Int("findings", len(auditResult.Findings)),
		zap.Int("warnings", len(auditWarnings)),
		zap.Duration("duration", time.Since(started)),
	)
	if req.Progress != nil {
		req.Progress.CompleteStage("Evaluating policy", 1)
	}
	return auditResult, auditWarnings
}

// runDetect is the detection stage: it resolves each subproject's graph and then
// consolidates them into the single graph and package registry the rest of the
// pipeline operates on. Consolidation is the tail of detection, not a separate stage.
func (p *Pipeline) runDetect(ctx context.Context, result *PipelineResult, req PipelineRequest) error {
	if err := p.runResolve(ctx, result, req); err != nil {
		return err
	}
	return p.runConsolidate(result)
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
	result.DetectorWarnings = append(result.DetectorWarnings, p.fallbackWarnings(resolveResults)...)
	return nil
}

// fallbackWarnings converts fallback annotations recorded during parallel
// resolution into structured warnings and Warn logs. It runs single-goroutine
// after resolveAll returns, so no synchronization is needed.
func (p *Pipeline) fallbackWarnings(results []sdk.DetectionResult) []PipelineWarning {
	var warnings []PipelineWarning
	seen := make(map[string]struct{})
	for _, result := range results {
		if result.FallbackFrom == "" {
			continue
		}
		key := result.SubprojectInfo.RelativePath + "\x00" + result.FallbackFrom + "\x00" + result.DetectorName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.Logger.Warn("pipeline: detector fell back",
			zap.String("detector", result.FallbackFrom),
			zap.String("fallback_detector", result.DetectorName),
			zap.String("subproject", result.SubprojectInfo.RelativePath),
			zap.String("reason", result.FallbackReason),
		)
		warnings = append(warnings, PipelineWarning{Source: result.FallbackFrom, Message: fallbackWarningMessage(result)})
	}
	return warnings
}

func fallbackWarningMessage(result sdk.DetectionResult) string {
	var b strings.Builder
	if rel := strings.TrimSpace(result.SubprojectInfo.RelativePath); rel != "" && rel != "." {
		fmt.Fprintf(&b, "subproject %s: ", rel)
	}
	reason := result.FallbackReason
	if reason == "" {
		reason = "primary detector failed"
	}
	fmt.Fprintf(&b, "%s — fell back to %s (transitive dependencies may be missing)", reason, result.DetectorName)
	return b.String()
}

func (p *Pipeline) runConsolidate(result *PipelineResult) error {
	started := time.Now()
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
	packages := 0
	if selectedGraph != nil {
		packages = selectedGraph.Size()
	}
	p.Logger.Info("pipeline: consolidation completed",
		zap.Int("resolve_results", len(result.ResolveResults)),
		zap.Int("manifests", len(consolidated.Manifests)),
		zap.Int("subprojects", len(consolidated.Subprojects)),
		zap.Int("packages", packages),
		zap.Duration("duration", time.Since(started)),
	)
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
		if root.Type == sdk.PackageTypeApplication {
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
	started := time.Now()
	p.Logger.Info("pipeline: enrichment started", zap.Int("packages", result.Graph.Size()))
	p.match(ctx, result, req)
	p.Logger.Info("pipeline: enrichment completed",
		zap.Int("matchers", len(result.MatcherStats)),
		zap.Int("warnings", len(result.MatchWarnings)),
		zap.Duration("duration", time.Since(started)),
	)
	if req.Progress != nil {
		req.Progress.CompleteStage("Enriching packages", 1)
	}
}

// runAnalyze runs the reachability analyzer stage when --analyze is
// set. Errors degrade to warnings; analyzer failure must never abort the
// pipeline.
func (p *Pipeline) runAnalyze(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if !req.AnalyzeReachabilityEnabled || result.Graph == nil {
		return
	}
	if req.Progress != nil {
		req.Progress.StartStage("Analyzing reachability", 1)
	}
	started := time.Now()
	p.Logger.Info("pipeline: reachability analysis started", zap.Int("packages", result.Graph.Size()))
	p.analyze(ctx, result, req)
	p.Logger.Info("pipeline: reachability analysis completed",
		zap.Strings("analyzer_runs", result.AnalyzerRuns),
		zap.Int("warnings", len(result.AnalyzeWarnings)),
		zap.Duration("duration", time.Since(started)),
	)
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
	auditResult, auditWarnings := p.runAuditStage(ctx, result.Graph, result.Registry, req)
	result.Findings = auditResult.Findings
	result.RiskScores = auditResult.RiskScores
	result.AuditorRuns = auditResult.AuditorRuns
	result.AuditorFindings = auditResult.AuditorFindings
	result.AuditWarnings = append(result.AuditWarnings, auditWarnings...)
}

func (p *Pipeline) match(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if result.Graph == nil {
		return
	}
	mReq := sdk.MatchRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Graph:           result.Graph,
		Registry:        result.Registry,
		MatcherFilter:   req.MatcherFilter,
		Stderr:          req.Stderr,
	}
	matchResult, err := p.engine.Match(ctx, mReq)
	result.MatcherStats = matchResult.MatcherStats
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
