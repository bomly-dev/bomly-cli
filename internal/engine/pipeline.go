package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/remediation"
	"github.com/bomly-dev/bomly-sdk"
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
// warn-only policy-status rewriting, stage progress, and Info-level
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
	auditResult.Findings = p.applyFindingPolicy(ctx, auditResult.Findings, registry, req)
	p.Logger.Info("pipeline: policy evaluation completed",
		zap.Strings("auditor_runs", auditResult.AuditorRuns),
		zap.Int("findings", len(auditResult.Findings)),
		zap.Int("accepted", acceptedFindingCount(auditResult.Findings)),
		zap.Int("warnings", len(auditWarnings)),
		zap.Duration("duration", time.Since(started)),
	)
	if req.Progress != nil {
		req.Progress.CompleteStage("Evaluating policy", 1)
	}
	return auditResult, auditWarnings
}

func (p *Pipeline) applyFindingPolicy(ctx context.Context, findings []sdk.Finding, registry *sdk.PackageRegistry, req PipelineRequest) []sdk.Finding {
	beforeAccepted := acceptedFindingCount(findings)
	started := time.Now()
	resolved := applyFindingPolicy(ctx, findings, registry, req)
	if req.BaselineEvaluation != nil {
		accepted := acceptedFindingCount(resolved) - beforeAccepted
		if accepted < 0 {
			accepted = 0
		}
		p.Logger.Info("baseline: policy evaluation completed",
			zap.String("path", req.BaselineEvaluation.Path),
			zap.Int("entries", req.BaselineEvaluation.Entries),
			zap.Bool("automatic", req.BaselineEvaluation.Automatic),
			zap.Int("findings_evaluated", len(findings)),
			zap.Int("findings_accepted", accepted),
			zap.Duration("duration", time.Since(started)))
	}
	return resolved
}

func applyFindingPolicy(ctx context.Context, findings []sdk.Finding, registry *sdk.PackageRegistry, req PipelineRequest) []sdk.Finding {
	if req.WarnOnly {
		for idx := range findings {
			if findings[idx].PolicyStatus == "" || findings[idx].PolicyStatus == sdk.FindingPolicyStatusFail {
				findings[idx].PolicyStatus = sdk.FindingPolicyStatusWarn
			}
		}
	}
	return resolveFindingPolicyStatuses(ctx, findings, registry, req.FindingPolicyResolvers)
}

func acceptedFindingCount(findings []sdk.Finding) int {
	total := 0
	for _, finding := range findings {
		if finding.PolicyStatus == sdk.FindingPolicyStatusSuppressed {
			total++
		}
	}
	return total
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
		result.DetectorWarnings = resolutionFailureWarnings(resolveErr)
		p.Logger.Warn("pipeline: partial resolution failures", zap.Error(resolveErr))
	}
	result.DetectorWarnings = append(result.DetectorWarnings, p.fallbackWarnings(resolveResults)...)
	result.DetectorWarnings = append(result.DetectorWarnings, p.detectorReportedWarnings(resolveResults)...)
	return nil
}

// resolutionFailureWarnings converts the (possibly joined) resolution error into
// one warning per failed detector chain. The scan continues without those
// subprojects, so the graph is incomplete: the type says so.
func resolutionFailureWarnings(err error) []sdk.DetectorWarning {
	warnings := make([]sdk.DetectorWarning, 0)
	for _, warning := range PipelineWarningsFromError(err, "detector") {
		warnings = append(warnings, sdk.DetectorWarning{
			Type:    sdk.DetectorWarningResolutionFailure,
			Source:  warning.Source,
			Message: warning.Message,
		})
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

// fallbackWarnings converts fallback annotations recorded during parallel
// resolution into structured warnings and Warn logs. It runs single-goroutine
// after resolveAll returns, so no synchronization is needed.
func (p *Pipeline) fallbackWarnings(results []sdk.DetectionResult) []sdk.DetectorWarning {
	var warnings []sdk.DetectorWarning
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
		warnings = append(warnings, sdk.DetectorWarning{
			Type:       sdk.DetectorWarningFallback,
			Source:     result.FallbackFrom,
			Subproject: result.SubprojectInfo.RelativePath,
			Manifest:   firstManifestPath(result),
			Message:    fallbackWarningMessage(result),
		})
	}
	return warnings
}

func fallbackWarningMessage(result sdk.DetectionResult) string {
	var b strings.Builder
	reason := result.FallbackReason
	if reason == "" {
		reason = "primary detector failed"
	}
	fmt.Fprintf(&b, "%s unavailable (%s) — resolved with %s; transitive dependencies may be missing",
		result.FallbackFrom, reason, result.DetectorName)
	return b.String()
}

// firstManifestPath names a manifest the result produced, so a warning can point
// at a file. Fallback provenance is recorded on every manifest of the result;
// one is enough to locate it.
func firstManifestPath(result sdk.DetectionResult) string {
	if result.Graphs == nil {
		return ""
	}
	for _, entry := range result.Graphs.Entries {
		if path := strings.TrimSpace(entry.Manifest.Path); path != "" {
			// Detector paths can be absolute inside a temporary clone; carry the
			// same relative form the consolidated manifests use.
			return consolidation.NormalizeManifestPath(result.SubprojectInfo, path)
		}
	}
	return ""
}

// detectorReportedWarnings collects the warnings detectors returned with their
// graphs, stamping the subproject they came from and logging each one so `-v`
// shows them when progress output is off (`-q`) or the run has no terminal.
// Duplicates (a repo-root config shared by several subproject results) are
// reported once. Like fallbackWarnings, this runs single-goroutine after
// resolveAll returns.
func (p *Pipeline) detectorReportedWarnings(results []sdk.DetectionResult) []sdk.DetectorWarning {
	var warnings []sdk.DetectorWarning
	seen := make(map[string]struct{})
	for _, result := range results {
		for _, warning := range result.Warnings {
			if warning.Subproject == "" {
				warning.Subproject = result.SubprojectInfo.RelativePath
			}
			key := string(warning.Type) + "\x00" + string(warning.Code) + "\x00" + warning.Source +
				"\x00" + warning.Subproject + "\x00" + warning.Manifest + "\x00" + warning.Message
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			p.Logger.Warn("pipeline: detector warning",
				zap.String("type", string(warning.Type)),
				zap.String("code", string(warning.Code)),
				zap.String("source", warning.Source),
				zap.String("detector", result.DetectorName),
				zap.String("subproject", warning.Subproject),
				zap.String("manifest", warning.Manifest),
				zap.String("message", warning.Message),
			)
			warnings = append(warnings, warning)
		}
	}
	return warnings
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
		rootIDs = append(rootIDs, root.NodeID())
		// A module root is the project's own artifact, which is what this
		// warning is about: dependencies hanging off the scanned project with
		// no stated relationship. An application-typed dependency node is a
		// consumed package and does not make the graph a project graph.
		if root.Kind() == sdk.NodeKindModule {
			hasApplicationRoot = true
		}
	}
	if !hasApplicationRoot {
		return
	}
	p.Logger.Debug(
		"pipeline: dependency components with unknown parent relationships detected",
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
	eligible := 0
	// Counted separately from the graph's size, which includes the module and
	// manifest nodes a normal graph now has. Subtracting from the size
	// reported one excluded package for every structural node -- so a graph
	// whose ten dependencies were all eligible still claimed an exclusion,
	// contradicting the comment below it and sending anyone reading -v after
	// a missing enrichment.
	candidates := 0
	result.Graph.WalkNodes(func(graphNode sdk.GraphNode) bool {
		// Only dependency nodes are ever enriched: a manifest or a module is
		// the project's own artifact, and there is no registry to ask about
		// it. They are not counted as excluded either -- they were never
		// candidates.
		dependency, ok := graphNode.(*sdk.DependencyNode)
		if !ok {
			return true
		}
		candidates++
		if dependency.RegistryMatchEligible() {
			eligible++
		} else {
			p.Logger.Debug("pipeline: dependency excluded from registry enrichment",
				zap.String("dependency_id", dependency.NodeID()),
				zap.String("source", string(dependency.Source)),
				zap.String("type", string(dependency.Type)))
		}
		return true
	})
	p.Logger.Info("pipeline: enrichment started",
		zap.Int("packages", candidates),
		zap.Int("eligible_packages", eligible),
		zap.Int("excluded_packages", candidates-eligible),
		zap.Int("graph_nodes", result.Graph.Size()))
	p.match(ctx, result, req)
	if req.EnrichEnabled {
		detectors := remediationDetectorsByName(p.Registry.AllDetectors())
		for _, warning := range remediation.Derive(ctx, remediation.Input{
			ProjectPath: req.ProjectPath,
			Registry:    result.Registry,
			Manifests:   result.Consolidated.Manifests,
			Detections:  result.ResolveResults,
			Detectors:   detectors,
		}) {
			result.MatchWarnings = append(result.MatchWarnings, PipelineWarning{
				Source:  warning.Source,
				Message: warning.Message,
			})
			p.Logger.Warn("pipeline: detector remediation evidence rejected",
				zap.String("detector", warning.Source),
				zap.String("reason", warning.Message))
		}
	}
	remediationPackages, remediationSuggestions := remediationCounts(result.Registry)
	p.Logger.Info("pipeline: enrichment completed",
		zap.Int("matchers", len(result.MatcherStats)),
		zap.Int("warnings", len(result.MatchWarnings)),
		zap.Int("remediation_packages", remediationPackages),
		zap.Int("remediation_suggestions", remediationSuggestions),
		zap.Duration("duration", time.Since(started)),
	)
	if req.Progress != nil {
		req.Progress.CompleteStage("Enriching packages", 1)
	}
}

func remediationCounts(registry *sdk.PackageRegistry) (packages, suggestions int) {
	if registry == nil {
		return 0, 0
	}
	for _, pkg := range registry.All() {
		if pkg == nil || pkg.Remediation == nil {
			continue
		}
		packages++
		suggestions += len(pkg.Remediation.Suggestions)
	}
	return packages, suggestions
}

func remediationDetectorsByName(detectors []sdk.Detector) map[string]sdk.Detector {
	result := make(map[string]sdk.Detector)
	var add func(sdk.Detector)
	add = func(detector sdk.Detector) {
		if detector == nil {
			return
		}
		name := detector.Descriptor().Name
		if _, exists := result[name]; exists {
			return
		}
		result[name] = detector
		//nolint:staticcheck // deprecated interface still consulted during its one-release compatibility window
		if provider, ok := detector.(sdk.FallbackDetector); ok {
			add(provider.FallbackDetector())
		}
	}
	for _, detector := range detectors {
		add(detector)
	}
	return result
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
	if matchResult.VulnerabilitiesConsolidated > 0 {
		p.Logger.Info("pipeline: alias-equivalent vulnerabilities consolidated",
			zap.Int("records_removed", matchResult.VulnerabilitiesConsolidated))
	}
	if err != nil {
		result.MatchWarnings = PipelineWarningsFromError(err, "matcher")
		p.Logger.Warn("pipeline: matcher enrichment error", zap.Error(err))
	}
}

func (p *Pipeline) audit(ctx context.Context, g *sdk.Graph, registry *sdk.PackageRegistry, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
	auditReq := sdk.AuditRequest{
		ProjectPath:             req.ProjectPath,
		ExecutionTarget:         req.ExecutionTarget,
		Graph:                   g,
		Registry:                registry,
		BaselineGraph:           req.BaselineGraph,
		DependencyDetailChanges: sdk.CloneDependencyDetailTransitions(req.DependencyDetailChanges),
		AuditorFilter:           req.AuditorFilter,
		Stderr:                  req.Stderr,
	}
	result, err := p.engine.Audit(ctx, auditReq)
	var warnings []PipelineWarning
	if err != nil {
		warnings = PipelineWarningsFromError(err, "auditor")
		p.Logger.Warn("pipeline: audit errors", zap.Error(err))
	}
	return result, warnings
}

func (p *Pipeline) auditComponent(ctx context.Context, g *sdk.Graph, registry *sdk.PackageRegistry, target *sdk.DependencyNode, req PipelineRequest) (sdk.AuditResult, []PipelineWarning) {
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
	result.Findings = p.applyFindingPolicy(ctx, result.Findings, registry, req)
	var warnings []PipelineWarning
	if err != nil {
		warnings = PipelineWarningsFromError(err, "auditor")
		p.Logger.Warn("pipeline: component audit errors", zap.Error(err))
	}
	return result, warnings
}
