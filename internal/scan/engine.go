package scan

import (
	"context"
	"errors"
	"fmt"
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
		registry = NewRegistry()
	}
	return &Engine{registry: registry}
}

// Audit selects auditors by priority and aggregates their findings.
func (e *Engine) Audit(ctx context.Context, req AuditRequest) (AuditResult, error) {
	auditors := e.registry.Auditors(req)
	if len(auditors) == 0 {
		return AuditResult{}, fmt.Errorf("%w for ecosystem %q, package manager %q, and mode %q", ErrNoAuditor, req.Ecosystem, req.PackageManager, req.Mode)
	}

	aggregated := AuditResult{
		Graph:           req.Graph,
		Target:          req.Target,
		AuditorFindings: make(map[string]int),
	}
	var errs []error
	for _, auditor := range auditors {
		name := auditor.Descriptor().Name
		if readyAuditor, ok := auditor.(ReadyAuditor); ok && !readyAuditor.Ready() {
			errs = append(errs, fmt.Errorf("auditor %s: not ready", name))
			continue
		}
		if applicableAuditor, ok := auditor.(ApplicableAuditor); ok {
			applicable, err := applicableAuditor.Applicable(ctx, req)
			if err != nil {
				errs = append(errs, fmt.Errorf("auditor %s: applicability check failed: %w", name, err))
				continue
			}
			if !applicable {
				errs = append(errs, fmt.Errorf("auditor %s: not applicable", name))
				continue
			}
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
func (e *Engine) Match(ctx context.Context, req MatchRequest) (MatchResult, error) {
	matchers := e.registry.Matchers(req)
	if len(matchers) == 0 {
		return MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}

	aggregated := MatchResult{
		Graph:  req.Graph,
		Target: req.Target,
	}
	var errs []error
	for _, matcher := range matchers {
		name := matcher.Descriptor().Name
		if readyMatcher, ok := matcher.(ReadyMatcher); ok && !readyMatcher.Ready() {
			errs = append(errs, fmt.Errorf("matcher %s: not ready", name))
			continue
		}
		if applicableMatcher, ok := matcher.(ApplicableMatcher); ok {
			applicable, err := applicableMatcher.Applicable(ctx, req)
			if err != nil {
				errs = append(errs, fmt.Errorf("matcher %s: applicability check failed: %w", name, err))
				continue
			}
			if !applicable {
				errs = append(errs, fmt.Errorf("matcher %s: not applicable", name))
				continue
			}
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
