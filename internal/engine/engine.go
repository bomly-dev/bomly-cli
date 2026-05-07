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
		return sdk.AuditResult{}, fmt.Errorf("%w for ecosystem %q, package manager %q, and mode %q", ErrNoAuditor, req.Ecosystem, req.PackageManager, req.Mode)
	}

	aggregated := sdk.AuditResult{
		Graph:           req.Graph,
		Target:          req.Target,
		AuditorFindings: make(map[string]int),
	}
	var errs []error
	for _, auditor := range auditorsList {
		name := auditor.Descriptor().Name
		if !auditor.Ready() {
			errs = append(errs, fmt.Errorf("auditor %s: not ready", name))
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
		aggregated.AuditorRuns = append(aggregated.AuditorRuns, name)
		aggregated.AuditorFindings[name] += len(result.Findings)
		aggregated.Findings = append(aggregated.Findings, result.Findings...)
		aggregated.RiskScores = append(aggregated.RiskScores, result.RiskScores...)
		if aggregated.Graph == nil {
			aggregated.Graph = result.Graph
		}
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}

// Match runs registered matchers against the graph and returns the enriched graph.
func (e *Engine) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	matcherList := e.registry.Matchers(req)
	if len(matcherList) == 0 {
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}

	aggregated := sdk.MatchResult{
		Graph:  req.Graph,
		Target: req.Target,
	}
	var errs []error
	for _, matcher := range matcherList {
		name := matcher.Descriptor().Name
		if !matcher.Ready() {
			errs = append(errs, fmt.Errorf("matcher %s: not ready", name))
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
		aggregated.MatcherRuns = append(aggregated.MatcherRuns, name)
		if result.Graph != nil {
			aggregated.Graph = result.Graph
			req.Graph = result.Graph
		}
		if result.Target != nil {
			aggregated.Target = result.Target
			req.Target = result.Target
		}
	}
	if len(errs) > 0 {
		return aggregated, errors.Join(errs...)
	}
	return aggregated, nil
}
