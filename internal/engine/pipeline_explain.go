package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/engine/explain"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// ExplainRequest defines input for an explain pipeline run.
type ExplainRequest struct {
	Query    string
	Pipeline PipelineRequest
}

// ExplainTarget contains one selected manifest where the queried dependency exists.
type ExplainTarget struct {
	Manifest     sdk.ConsolidatedManifest
	Dependency   *sdk.Package
	Paths        []explain.Path
	Findings     []sdk.Finding
	FocusedGraph *sdk.Graph
}

// ExplainResult contains full and focused explain pipeline output.
type ExplainResult struct {
	PipelineResult
	Targets             []ExplainTarget
	FocusedConsolidated sdk.ConsolidatedGraph
	FocusedGraph        *sdk.Graph
}

// RunExplain resolves, enriches, and optionally audits selected manifests for an explain query.
func (p *Pipeline) RunExplain(ctx context.Context, req ExplainRequest) (ExplainResult, error) {
	pipeReq := req.Pipeline
	auditEnabled := pipeReq.AuditEnabled
	pipeReq.AuditEnabled = false

	base := PipelineResult{}
	if err := p.runPre(ctx, pipeReq); err != nil {
		return ExplainResult{PipelineResult: base}, err
	}
	if err := p.runResolve(ctx, &base, pipeReq); err != nil {
		return ExplainResult{PipelineResult: base}, err
	}
	if err := p.runScopeFilter(&base, pipeReq); err != nil {
		return ExplainResult{PipelineResult: base}, err
	}
	if err := p.runConsolidate(&base, pipeReq); err != nil {
		return ExplainResult{PipelineResult: base}, err
	}
	p.runMatch(ctx, &base, pipeReq)

	result := ExplainResult{PipelineResult: base}
	focusedResults := make([]sdk.DetectionResult, 0, len(base.Consolidated.Manifests))
	allFindings := make([]sdk.Finding, 0)
	auditorFindings := make(map[string]int)

	for _, manifest := range base.Consolidated.Manifests {
		g := manifest.Entry.Graph
		dependency, paths, err := explain.FindWhyPackage(g, req.Query)
		if err != nil {
			if errors.Is(err, explain.ErrDependencyNotFound) {
				continue
			}
			return result, fmt.Errorf("explain dependency paths: %w", err)
		}

		var findings []sdk.Finding
		if auditEnabled {
			auditResult, warnings := p.auditComponent(ctx, g, dependency, pipeReq)
			findings = auditResult.Findings
			allFindings = append(allFindings, findings...)
			result.AuditWarnings = append(result.AuditWarnings, warnings...)
			result.AuditorRuns = appendUnique(result.AuditorRuns, auditResult.AuditorRuns...)
			for name, count := range auditResult.AuditorFindings {
				auditorFindings[name] += count
			}
			result.RiskScores = append(result.RiskScores, auditResult.RiskScores...)
		}

		focusedGraph, err := explain.GraphFromPaths(g, paths)
		if err != nil {
			return result, fmt.Errorf("focused explain graph: %w", err)
		}
		result.Targets = append(result.Targets, ExplainTarget{
			Manifest:     manifest,
			Dependency:   dependency,
			Paths:        paths,
			Findings:     findings,
			FocusedGraph: focusedGraph,
		})
		focusedResults = append(focusedResults, sdk.DetectionResult{
			SubprojectInfo: manifest.Subproject,
			DetectorName:   manifest.DetectorName,
			Origin:         manifest.Origin,
			Technique:      manifest.Technique,
			Graphs:         sdk.SingleGraphContainer(focusedGraph, manifest.Entry.Manifest),
		})
	}

	if len(result.Targets) == 0 {
		return result, fmt.Errorf("%w: %s", explain.ErrDependencyNotFound, req.Query)
	}

	if auditEnabled && !GraphHasVulnerabilityData(base.Graph) {
		result.AuditWarnings = append(result.AuditWarnings, PipelineWarning{
			Source:  "severity-policy",
			Message: "no vulnerability enrichment input was available; policy evaluation may produce no findings",
		})
	}
	result.Findings = DeduplicateFindings(allFindings)
	result.AuditorFindings = auditorFindings

	focusedConsolidated, err := consolidation.ConsolidateGraphs(focusedResults)
	if err != nil {
		return result, fmt.Errorf("focused explain consolidation: %w", err)
	}
	result.FocusedConsolidated = focusedConsolidated
	focusedGraph, err := focusedConsolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		return result, fmt.Errorf("focused explain graph: %w", err)
	}
	result.FocusedGraph = focusedGraph

	postResult := result.PipelineResult
	postResult.Consolidated = focusedConsolidated
	postResult.Graph = focusedGraph
	postResult.Findings = result.Findings
	postResult.AuditWarnings = result.AuditWarnings
	postResult.AuditorRuns = result.AuditorRuns
	postResult.AuditorFindings = result.AuditorFindings
	p.runPost(ctx, pipeReq, postResult)

	return result, nil
}

func appendUnique(values []string, candidates ...string) []string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		found := false
		for _, value := range values {
			if value == candidate {
				found = true
				break
			}
		}
		if !found {
			values = append(values, candidate)
		}
	}
	return values
}
