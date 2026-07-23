package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
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
	Registry                    *sdk.PackageRegistry
	MatcherStats                []sdk.MatcherStats
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
func (e *Engine) Audit(ctx context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	auditorsList := e.registry.Auditors(req)
	if len(auditorsList) == 0 {
		return sdk.AuditResult{}, fmt.Errorf("%w for ecosystem %q, and package manager %q", ErrNoAuditor, req.Ecosystem, req.PackageManager)
	}

	aggregated := sdk.AuditResult{
		AuditorFindings: make(map[string]int),
	}
	var errs []error
	for _, auditor := range auditorsList {
		descriptor := auditor.Descriptor()
		name := descriptor.Name
		label := descriptor.Label()
		if err := auditor.Ready(ctx, req); err != nil {
			errs = append(errs, fmt.Errorf("auditor %s: not ready: %w", name, err))
			continue
		}
		applicable, err := auditor.Applicable(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("auditor %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			errs = append(errs, fmt.Errorf("auditor %s: not applicable", name))
			continue
		}

		result, err := auditor.Audit(ctx, req)
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

// Analyze runs registered analyzers against the graph and returns the
// reachability-annotated graph. Unlike Audit, Analyze does NOT error when
// zero analyzers apply — reachability is opt-in and a request with no
// applicable analyzers is a normal outcome.
func (e *Engine) Analyze(ctx context.Context, req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
	analyzers := e.registry.Analyzers(req)
	if len(analyzers) == 0 {
		return sdk.AnalyzeResult{Registry: req.Registry}, nil
	}

	aggregated := sdk.AnalyzeResult{
		Registry:      req.Registry,
		AnalyzerStats: make(map[string]sdk.ReachabilityStats),
	}
	var errs []error
	for _, analyzer := range analyzers {
		descriptor := analyzer.Descriptor()
		name := descriptor.Name
		label := descriptor.Label()
		if err := analyzer.Ready(ctx, req); err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: not ready: %w", name, err))
			continue
		}
		applicable, err := analyzer.Applicable(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			continue
		}

		result, err := analyzer.Analyze(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("analyzer %s: %w", name, err))
			continue
		}
		aggregated.AnalyzerRuns = append(aggregated.AnalyzerRuns, label)
		if result.Registry != nil {
			aggregated.Registry = result.Registry
			req.Registry = result.Registry
		}
		for analyzerName, stats := range result.AnalyzerStats {
			aggregated.AnalyzerStats[analyzerName] = stats
		}
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

// Match runs registered matchers against the graph and returns the enriched graph.
func (e *Engine) Match(ctx context.Context, req sdk.MatchRequest) (MatchResult, error) {
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
		return MatchResult{Registry: req.Registry}, nil
	}
	matcherList := e.registry.Matchers(req)
	if len(matcherList) == 0 {
		return MatchResult{Registry: req.Registry}, fmt.Errorf("%w for ecosystem %q, and package manager %q", ErrNoMatcher, req.Ecosystem, req.PackageManager)
	}

	aggregated := MatchResult{
		Registry: req.Registry,
	}
	var errs []error
	for _, matcher := range matcherList {
		descriptor := matcher.Descriptor()
		name := descriptor.Name
		if err := matcher.Ready(ctx, req); err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: not ready: %w", name, err))
			continue
		}
		applicable, err := matcher.Applicable(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: applicability check failed: %w", name, err))
			continue
		}
		if !applicable {
			errs = append(errs, fmt.Errorf("matcher %s: not applicable", name))
			continue
		}

		result, err := matcher.Match(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("matcher %s: %w", name, err))
			continue
		}
		aggregated.MatcherStats = append(aggregated.MatcherStats, matcherStats(descriptor, result.MatcherStats))
		if result.Registry != nil {
			aggregated.Registry = result.Registry
			req.Registry = result.Registry
		}
	}
	if aggregated.Registry != nil {
		before, after := consolidateRegistryVulnerabilities(aggregated.Registry)
		aggregated.VulnerabilitiesConsolidated = before - after
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

func matcherStats(descriptor sdk.MatcherDescriptor, stats sdk.MatcherStats) sdk.MatcherStats {
	if stats.Name == "" {
		stats.Name = descriptor.Name
	}
	if stats.DisplayName == "" {
		stats.DisplayName = descriptor.DisplayName
	}
	return stats
}
