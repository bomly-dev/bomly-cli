package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

var (
	// ErrNoAuditor indicates no auditor supports a request.
	ErrNoAuditor = errors.New("no auditor available")
	// ErrNoMatcher indicates no matcher supports a request.
	ErrNoMatcher = errors.New("no matcher available")
)

// MatchResult contains aggregate matcher output after the engine runs all
// selected matchers for a pipeline stage.
type MatchResult struct {
	Registry                    *model.PackageRegistry
	MatcherStats                []plugin.MatcherStats
	VulnerabilitiesConsolidated int
}

// Engine orchestrates detector and auditor execution.
type Engine struct {
	registry *Registry
}

// NewEngine creates a scan engine with the provided registry.
func NewEngine(registry *Registry) *Engine {
	if registry == nil {
		registry = NewRegistry(RegistryConfigs{}, *zap.NewNop())
	}
	return &Engine{registry: registry}
}

// Audit selects auditors by priority and aggregates their findings.
func (e *Engine) Audit(ctx context.Context, req plugin.AuditRequest) (plugin.AuditResult, error) {
	auditorsList := e.registry.Auditors(req)
	if len(auditorsList) == 0 {
		return plugin.AuditResult{}, fmt.Errorf("%w for ecosystem %q, and package manager %q", ErrNoAuditor, req.Ecosystem, req.PackageManager)
	}

	aggregated := plugin.AuditResult{
		AuditorFindings: make(map[string]int),
	}
	var errs []error
	for _, auditor := range auditorsList {
		descriptor := auditor.Descriptor()
		name := descriptor.Name
		label := descriptor.Label()
		if err := auditor.Ready(ctx, cloneAuditRequest(req)); err != nil {
			errs = append(errs, fmt.Errorf("auditor %s: not ready: %w", name, err))
			continue
		}
		applicable, err := auditor.Applicable(ctx, cloneAuditRequest(req))
		if err != nil {
			errs = append(errs, fmt.Errorf("auditor %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			errs = append(errs, fmt.Errorf("auditor %s: not applicable", name))
			continue
		}

		result, err := auditor.Audit(ctx, cloneAuditRequest(req))
		if err != nil {
			errs = append(errs, fmt.Errorf("auditor %s: %w", name, err))
			continue
		}
		aggregated.AuditorRuns = append(aggregated.AuditorRuns, label)
		aggregated.AuditorFindings[label] += len(result.Findings)
		aggregated.Findings = append(aggregated.Findings, result.Findings...)
		aggregated.RiskScores = append(aggregated.RiskScores, result.RiskScores...)
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

func cloneAuditRequest(req plugin.AuditRequest) plugin.AuditRequest {
	cloned := req
	cloned.DependencyDetailChanges = model.CloneDependencyDetailTransitions(req.DependencyDetailChanges)
	return cloned
}

// Analyze runs registered analyzers against the graph and returns the
// reachability-annotated graph. Each call is a transaction over its own
// AnalyzeRequest.Clone, committed only on success, exactly as Match's are. Unlike Audit, Analyze does NOT error when
// zero analyzers apply — reachability is opt-in and a request with no
// applicable analyzers is a normal outcome.
func (e *Engine) Analyze(ctx context.Context, req plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
	analyzers := e.registry.Analyzers(req)
	if len(analyzers) == 0 {
		return plugin.AnalyzeResult{Registry: req.Registry}, nil
	}

	// The engine understands AnalyzeResult.PackageUpdates deltas, so advertise
	// it to every analyzer, embedded or external.
	req.AcceptPackageUpdates = true

	aggregated := plugin.AnalyzeResult{
		Registry:      req.Registry,
		AnalyzerStats: make(map[string]plugin.ReachabilityStats),
	}
	var errs []error
	for _, analyzer := range analyzers {
		descriptor := analyzer.Descriptor()
		name := descriptor.Name
		label := descriptor.Label()
		if err := analyzer.Ready(ctx, req.Clone()); err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: not ready: %w", name, err))
			continue
		}
		applicable, err := analyzer.Applicable(ctx, req.Clone())
		if err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			continue
		}

		result, err := analyzer.Analyze(ctx, req.Clone())
		if err = committable(ctx, err); err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: %w", name, err))
			continue
		}
		aggregated.AnalyzerRuns = append(aggregated.AnalyzerRuns, label)
		// A returned registry wins over deltas, mirroring the external-plugin
		// transport adapter (internal/plugin/registry.go externalAnalyzer.Analyze),
		// which resolves PackageUpdates into a full Registry before the engine
		// sees the result — so external plugin deltas are never applied twice.
		switch {
		case result.Registry != nil:
			aggregated.Registry = result.Registry
			req.Registry = result.Registry
		case len(result.PackageUpdates) > 0:
			updated := model.ApplyPackageUpdates(req.Registry, result.PackageUpdates)
			aggregated.Registry = updated
			req.Registry = updated
		}
		maps.Copy(aggregated.AnalyzerStats, result.AnalyzerStats)
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

// Match runs registered matchers against the graph and returns the enriched graph.
//
// Each call is a transaction over a snapshot (ADR-0050): every Ready,
// Applicable and Match call receives its own MatchRequest.Clone, so a matcher
// never holds the host's graph, registry or target. Only a successful Match
// is committed -- its Registry if it returned one, otherwise its
// PackageUpdates merged into the canonical registry -- and a failed or
// cancelled one leaves the canonical state exactly as the previous matcher
// left it. Changes a matcher makes to the graph or target are never
// committed, as they never were for a managed plugin, whose request crosses
// the wire as a copy.
func (e *Engine) Match(ctx context.Context, req plugin.MatchRequest) (MatchResult, error) {
	originalGraphSize := 0
	if req.Graph != nil {
		originalGraphSize = req.Graph.Size()
	}
	hadTarget := req.Target != nil
	prepared, err := registryMatchRequest(req)
	if err != nil {
		return MatchResult{Registry: req.Registry}, fmt.Errorf("prepare registry matching: %w", err)
	}
	req = prepared
	if req.Graph == nil || (req.Graph.Size() == 0 && (originalGraphSize > 0 || hadTarget)) {
		result := MatchResult{Registry: req.Registry}
		finalizeMatchResult(&result)
		return result, nil
	}
	matcherList := e.registry.Matchers(req)
	if len(matcherList) == 0 {
		result := MatchResult{Registry: req.Registry}
		finalizeMatchResult(&result)
		return result, fmt.Errorf("%w for ecosystem %q, and package manager %q", ErrNoMatcher, req.Ecosystem, req.PackageManager)
	}

	// The engine understands MatchResult.PackageUpdates deltas, so advertise
	// it to every matcher, embedded or external.
	req.AcceptPackageUpdates = true

	aggregated := MatchResult{
		Registry: req.Registry,
	}
	var errs []error
	for _, matcher := range matcherList {
		descriptor := matcher.Descriptor()
		name := descriptor.Name
		if err := matcher.Ready(ctx, req.Clone()); err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: not ready: %w", name, err))
			continue
		}
		applicable, err := matcher.Applicable(ctx, req.Clone())
		if err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			errs = append(errs, fmt.Errorf("matcher %s: not applicable", name))
			continue
		}

		result, err := matcher.Match(ctx, req.Clone())
		if err = committable(ctx, err); err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: %w", name, err))
			continue
		}
		aggregated.MatcherStats = append(aggregated.MatcherStats, matcherStats(descriptor, result.MatcherStats))
		// A returned registry wins over deltas, mirroring the external-plugin
		// transport adapter (internal/plugin/registry.go externalMatcher.Match),
		// which resolves PackageUpdates into a full Registry before the engine
		// sees the result — so external plugin deltas are never applied twice.
		switch {
		case result.Registry != nil:
			aggregated.Registry = result.Registry
			req.Registry = result.Registry
		case len(result.PackageUpdates) > 0:
			updated := model.ApplyPackageUpdates(req.Registry, result.PackageUpdates)
			aggregated.Registry = updated
			req.Registry = updated
		}
	}
	finalizeMatchResult(&aggregated)
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

// committable reports whether a component call's result may be committed:
// not when the call failed, and not when the command was cancelled while it
// ran, even if the component returned without an error -- a component that
// ignored its context may have returned partial work.
func committable(ctx context.Context, err error) error {
	if err != nil {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("cancelled: %w", ctxErr)
	}
	return nil
}

func finalizeMatchResult(result *MatchResult) {
	if result == nil || result.Registry == nil {
		return
	}
	before, after := consolidateRegistryVulnerabilities(result.Registry)
	result.VulnerabilitiesConsolidated = before - after
}

func matcherStats(descriptor plugin.MatcherDescriptor, stats plugin.MatcherStats) plugin.MatcherStats {
	if stats.Name == "" {
		stats.Name = descriptor.Name
	}
	if stats.DisplayName == "" {
		stats.DisplayName = descriptor.DisplayName
	}
	return stats
}
