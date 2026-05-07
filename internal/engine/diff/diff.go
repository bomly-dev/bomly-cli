// Package diff runs two engine pipelines and classifies their audit deltas.
package diff

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// Target describes one side of a diff pipeline run.
type Target struct {
	Pipeline *engine.Pipeline
	Request  engine.PipelineRequest
}

// Request defines input for a two-target diff pipeline run.
type Request struct {
	Base Target
	Head Target
}

// Audit groups finding deltas between two audited dependency states.
type Audit struct {
	Introduced []model.Finding
	Resolved   []model.Finding
	Persisted  []model.Finding
}

// Result contains fully resolved pipeline output for a dependency diff.
type Result struct {
	Base     engine.PipelineResult
	Head     engine.PipelineResult
	Audit    *Audit
	Findings []model.Finding
}

// Run executes the full pipeline for base and head targets and computes audit deltas.
func Run(ctx context.Context, req Request) (Result, error) {
	result := Result{}
	if req.Base.Pipeline == nil {
		return result, fmt.Errorf("base diff pipeline is nil")
	}
	if req.Head.Pipeline == nil {
		return result, fmt.Errorf("head diff pipeline is nil")
	}

	base, err := req.Base.Pipeline.Run(ctx, req.Base.Request)
	result.Base = base
	if err != nil {
		return result, fmt.Errorf("base pipeline: %w", err)
	}

	head, err := req.Head.Pipeline.Run(ctx, req.Head.Request)
	result.Head = head
	if err != nil {
		return result, fmt.Errorf("head pipeline: %w", err)
	}

	if req.Base.Request.AuditEnabled || req.Head.Request.AuditEnabled {
		result.Audit = AuditSummary(base.Findings, head.Findings)
		result.Findings = append(append([]model.Finding{}, head.Findings...), base.Findings...)
	}
	return result, nil
}

// AuditSummary computes introduced, resolved, and persisted findings.
func AuditSummary(baseFindings, headFindings []model.Finding) *Audit {
	introduced, resolved, persisted := diffFindingSets(baseFindings, headFindings)
	return &Audit{Introduced: introduced, Resolved: resolved, Persisted: persisted}
}

func diffFindingSets(baseFindings, headFindings []model.Finding) ([]model.Finding, []model.Finding, []model.Finding) {
	baseByKey := make(map[string]model.Finding, len(baseFindings))
	headByKey := make(map[string]model.Finding, len(headFindings))
	for _, finding := range baseFindings {
		baseByKey[diffFindingKey(finding)] = finding
	}
	for _, finding := range headFindings {
		headByKey[diffFindingKey(finding)] = finding
	}
	introduced := make([]model.Finding, 0)
	resolved := make([]model.Finding, 0)
	persisted := make([]model.Finding, 0)
	for key, finding := range headByKey {
		if _, ok := baseByKey[key]; ok {
			persisted = append(persisted, finding)
			continue
		}
		introduced = append(introduced, finding)
	}
	for key, finding := range baseByKey {
		if _, ok := headByKey[key]; ok {
			continue
		}
		resolved = append(resolved, finding)
	}
	return introduced, resolved, persisted
}

func diffFindingKey(finding model.Finding) string {
	packageID := ""
	if finding.Package != nil {
		packageID = finding.Package.ID
	}
	return fmt.Sprintf("%s|%s|%s|%s", finding.ID, finding.Kind, finding.Source, packageID)
}
