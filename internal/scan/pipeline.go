package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
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
		registry = NewRegistry()
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
// that need per-result processing before consolidation (e.g. explain, diff).
func (p *Pipeline) ResolveAll(ctx context.Context, req PipelineRequest) ([]ResolveGraphResult, error) {
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
	if req.ScopeFilter != ScopeUnknown {
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
	if req.ScopeFilter != ScopeUnknown {
		selectedGraph, err = FilterGraphByScope(selectedGraph, req.ScopeFilter)
		if err != nil {
			return result, fmt.Errorf("scope filter consolidated: %w", err)
		}
	}
	result.Graph = selectedGraph

	// 5. Matcher enrichment (on consolidated graph to avoid duplicate calls).
	if req.MatchEnabled && result.Graph != nil {
		p.match(ctx, &result, req)
	}

	// 6. Command-specific processing.
	if req.Processor != nil {
		if err := req.Processor(ctx, &result); err != nil {
			return result, fmt.Errorf("stage processor: %w", err)
		}
	}

	// 7. Audit.
	if req.AuditEnabled && result.Graph != nil {
		auditResult, auditWarnings := p.audit(ctx, result.Graph, req)
		result.Findings = auditResult.Findings
		result.RiskScores = auditResult.RiskScores
		result.AuditWarnings = auditWarnings
	}

	// 8. Post-resolve hooks.
	if err := p.runPostHooks(ctx, req, result); err != nil {
		p.Logger.Warn("pipeline: post-resolve hook error", zap.Error(err))
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Stage implementations
// ---------------------------------------------------------------------------

func (p *Pipeline) runPreHooks(ctx context.Context, req PipelineRequest) error {
	hooks := p.Registry.PreResolveHooks()
	for _, hook := range hooks {
		desc := hook.Descriptor()
		p.Logger.Debug("pipeline: running pre-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, PreResolveContext{
			ExecutionTarget: req.ExecutionTarget,
			Subprojects:     req.Subprojects,
			ProjectPath:     req.ProjectPath,
			Stderr:          req.Stderr,
		}); err != nil {
			return fmt.Errorf("hook %s: %w", desc.Name, err)
		}
	}
	return nil
}

func (p *Pipeline) runPostHooks(ctx context.Context, req PipelineRequest, result PipelineResult) error {
	hooks := p.Registry.PostResolveHooks()
	var errs []error
	for _, hook := range hooks {
		desc := hook.Descriptor()
		p.Logger.Debug("pipeline: running post-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, PostResolveContext{
			Consolidated: result.Consolidated,
			Findings:     result.Findings,
			ProjectPath:  req.ProjectPath,
			Stderr:       req.Stderr,
		}); err != nil {
			errs = append(errs, fmt.Errorf("hook %s: %w", desc.Name, err))
		}
	}
	return errors.Join(errs...)
}

// resolveAll resolves dependency graphs for each subproject using registered detectors.
func (p *Pipeline) resolveAll(ctx context.Context, req PipelineRequest) ([]ResolveGraphResult, error) {
	results := make([]ResolveGraphResult, 0, len(req.Subprojects))
	var errs []error

	for _, sub := range req.Subprojects {
		subResults, err := p.resolveSubproject(ctx, req, sub)
		if err != nil {
			errs = append(errs, fmt.Errorf("subproject %s (%s/%s): %w", sub.RelativePath, sub.Ecosystem, sub.PackageManager, err))
			continue
		}
		results = append(results, subResults...)
	}

	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}
	return results, nil
}

func (p *Pipeline) resolveSubproject(ctx context.Context, req PipelineRequest, sub Subproject) ([]ResolveGraphResult, error) {
	baseReq := ResolveGraphRequest{
		ProjectPath:     sub.ExecutionTarget.Location,
		ExecutionTarget: sub.ExecutionTarget,
		Subproject:      sub,
		Ecosystem:       sub.Ecosystem,
		PackageManager:  sub.PackageManager,
		DetectorFilter:  req.DetectorFilter,
		Mode:            TargetModeFullGraph,
		InstallFirst:    req.InstallFirst,
		InstallArgs:     req.InstallArgs,
		CoreVersion:     req.CoreVersion,
		Stderr:          req.Stderr,
		Verbose:         req.Verbose,
	}

	detectorNames := sub.PlannedDetectors
	if len(detectorNames) > 1 {
		detectorNames = detectorNames[:1]
	}
	detectors := p.Registry.PlannedDetectors(baseReq, detectorNames)
	if len(detectors) == 0 {
		return nil, fmt.Errorf("no detector registered for ecosystem %q and package manager %q", sub.Ecosystem, sub.PackageManager)
	}

	results, err := p.resolveDetectors(ctx, baseReq, detectors)
	if err != nil {
		return nil, err
	}
	for idx := range results {
		results[idx].RootExecutionTarget = req.ExecutionTarget
	}
	return results, nil
}

// resolveDetectors runs matched detectors in priority order. Detectors may
// provide their own fallback detector when they cannot produce a result.
func (p *Pipeline) resolveDetectors(ctx context.Context, req ResolveGraphRequest, detectors []Detector) ([]ResolveGraphResult, error) {
	var results []ResolveGraphResult
	var errs []error

	for _, detector := range detectors {
		detectorResults, err := p.resolveDetector(ctx, req, detector)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, detectorResults...)
	}

	if len(results) == 0 {
		return nil, errors.Join(errs...)
	}
	return results, nil
}

func (p *Pipeline) resolveDetector(ctx context.Context, req ResolveGraphRequest, detector Detector) ([]ResolveGraphResult, error) {
	descriptor := detector.Descriptor()

	if !detector.Ready() {
		p.Logger.Debug("pipeline: detector not ready", zap.String("detector", descriptor.Name))
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: not ready", descriptor.Name))
	}

	applicable, err := detector.Applicable(ctx, req)
	if err != nil {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: applicability check failed: %w", descriptor.Name, err))
	}
	if !applicable {
		p.Logger.Debug("pipeline: detector not applicable", zap.String("detector", descriptor.Name))
		return p.resolveFallback(ctx, req, detector, nil)
	}

	if req.InstallFirst {
		if installer, ok := detector.(InstallFirstDetector); ok {
			if err := installer.Install(ctx, req); err != nil {
				return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: install-first failed: %w", descriptor.Name, err))
			}
		}
	}

	result, err := detector.ResolveGraph(ctx, req)
	if err != nil {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: %w", descriptor.Name, err))
	}

	result.SubprojectInfo = req.Subproject
	result.DetectorName = descriptor.Name
	result.DetectorType = descriptor.ImplementationType
	p.Logger.Debug("pipeline: detector succeeded", zap.String("detector", descriptor.Name))
	return []ResolveGraphResult{result}, nil
}

func (p *Pipeline) resolveFallback(ctx context.Context, req ResolveGraphRequest, detector Detector, primaryErr error) ([]ResolveGraphResult, error) {
	fallbackProvider, ok := detector.(FallbackDetector)
	if !ok {
		return nil, primaryErr
	}
	fallback := fallbackProvider.FallbackDetector()
	if fallback == nil {
		return nil, primaryErr
	}
	results, fallbackErr := p.resolveDetector(ctx, req, fallback)
	if primaryErr == nil {
		return results, fallbackErr
	}
	if fallbackErr == nil {
		return results, nil
	}
	return nil, errors.Join(primaryErr, fallbackErr)
}

func (p *Pipeline) match(ctx context.Context, result *PipelineResult, req PipelineRequest) {
	if result.Graph == nil {
		return
	}
	mReq := MatchRequest{
		ProjectPath:     req.ProjectPath,
		ExecutionTarget: req.ExecutionTarget,
		Mode:            TargetModeFullGraph,
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

func (p *Pipeline) audit(ctx context.Context, g *model.Graph, req PipelineRequest) (AuditResult, []PipelineWarning) {
	auditReq := AuditRequest{
		ProjectPath:   req.ProjectPath,
		Mode:          TargetModeFullGraph,
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

// unwrapJoinedErrors splits an error returned by errors.Join into its parts.
func unwrapJoinedErrors(err error) []error {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		return u.Unwrap()
	}
	return []error{err}
}

// PipelineWarningsFromError converts a (possibly joined) error into structured
// pipeline warnings. It extracts the source name from error messages that follow
// the pattern "<prefix> <name>: <message>" (e.g. "auditor osv: not ready").
func PipelineWarningsFromError(err error, prefix string) []PipelineWarning {
	if err == nil {
		return nil
	}
	var warnings []PipelineWarning
	for _, e := range unwrapJoinedErrors(err) {
		source, message := parseWarningSource(e.Error(), prefix)
		warnings = append(warnings, PipelineWarning{Source: source, Message: message})
	}
	return warnings
}

// parseWarningSource extracts a component name from error text formatted as
// "<prefix> <name>: <rest>" (e.g. "auditor grype: not ready"). If the text does
// not match the pattern, the full text is returned as the message with an empty source.
func parseWarningSource(text, prefix string) (source, message string) {
	p := prefix + " "
	if !strings.HasPrefix(text, p) {
		return "", text
	}
	rest := text[len(p):]
	idx := strings.Index(rest, ": ")
	if idx < 0 {
		return "", text
	}
	return rest[:idx], rest[idx+2:]
}

// filterResultsByScope applies scope filtering to each graph entry in the results.
func filterResultsByScope(results []ResolveGraphResult, scope Scope) ([]ResolveGraphResult, error) {
	if scope == ScopeUnknown {
		return results, nil
	}
	filtered := make([]ResolveGraphResult, 0, len(results))
	for _, result := range results {
		if result.Graphs == nil {
			filtered = append(filtered, result)
			continue
		}
		entries := make([]GraphEntry, 0, len(result.Graphs.Entries))
		for _, entry := range result.Graphs.Entries {
			if entry.Graph == nil {
				entries = append(entries, entry)
				continue
			}
			graphView, err := FilterGraphByScope(entry.Graph, scope)
			if err != nil {
				return nil, err
			}
			entries = append(entries, GraphEntry{Graph: graphView, Manifest: entry.Manifest})
		}
		result.Graphs = &GraphContainer{Entries: entries}
		filtered = append(filtered, result)
	}
	return filtered, nil
}
