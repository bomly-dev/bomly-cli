// Package diff runs two engine pipelines and classifies their audit deltas.
package diff

import (
	"context"
	"errors"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
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

// diffAuditRootManifest is the synthetic manifest path the diff audit's root
// node declares. The root is a module node -- it stands for the scanned
// project, not a consumed package -- and its ID is minted from this path by
// the module grammar rather than being a hand-written constant, which the
// typed union no longer allows (ADR-0041).
const diffAuditRootManifest = "bomly-diff-audit-root"

// Run executes the full pipeline for base and head targets and computes audit deltas.
func Run(ctx context.Context, req Request) (Result, error) {
	result := Result{}
	if req.Base.Pipeline == nil {
		return result, fmt.Errorf("base diff pipeline is nil")
	}
	if req.Head.Pipeline == nil {
		return result, fmt.Errorf("head diff pipeline is nil")
	}

	base, err := req.Base.Pipeline.RunPreAudit(ctx, req.Base.Request)
	result.Base = base
	if err != nil {
		return result, fmt.Errorf("base pipeline: %w", err)
	}

	req.Head.Request.BaselineGraph = base.Graph
	head, err := req.Head.Pipeline.RunPreAudit(ctx, req.Head.Request)
	result.Head = head
	if err != nil {
		return result, fmt.Errorf("head pipeline: %w", err)
	}

	if req.Base.Request.AuditEnabled || req.Head.Request.AuditEnabled {
		graphDiff := model.Compare(base.Graph, head.Graph)
		baseAuditGraph, headAuditGraph, err := focusedAuditGraphs(graphDiff)
		if err != nil {
			return result, fmt.Errorf("focused audit graphs: %w", err)
		}
		req.Base.Request.DependencyDetailChanges = nil
		req.Head.Request.DependencyDetailChanges = model.CloneDependencyDetailTransitions(graphDiff.Transitions)
		baseAudit, baseWarnings := req.Base.Pipeline.RunAuditGraph(ctx, baseAuditGraph, base.Registry, req.Base.Request)
		result.Base.Findings = baseAudit.Findings
		result.Base.RiskScores = baseAudit.RiskScores
		result.Base.AuditorRuns = baseAudit.AuditorRuns
		result.Base.AuditorFindings = baseAudit.AuditorFindings
		result.Base.AuditWarnings = append(result.Base.AuditWarnings, baseWarnings...)

		headAudit, headWarnings := req.Head.Pipeline.RunAuditGraph(ctx, headAuditGraph, head.Registry, req.Head.Request)
		result.Head.Findings = headAudit.Findings
		result.Head.RiskScores = headAudit.RiskScores
		result.Head.AuditorRuns = headAudit.AuditorRuns
		result.Head.AuditorFindings = headAudit.AuditorFindings
		result.Head.AuditWarnings = append(result.Head.AuditWarnings, headWarnings...)

		result.Audit = AuditSummary(result.Base.Findings, result.Head.Findings)
		result.Findings = append(append([]model.Finding{}, result.Head.Findings...), result.Base.Findings...)
	}
	return result, nil
}

func focusedAuditGraphs(graphDiff model.Diff) (*model.Graph, *model.Graph, error) {
	basePackages := make([]*model.DependencyNode, 0, len(graphDiff.Removed)+len(graphDiff.Updated))
	headPackages := make([]*model.DependencyNode, 0, len(graphDiff.Added)+len(graphDiff.Updated))
	basePackages = append(basePackages, graphDiff.Removed...)
	headPackages = append(headPackages, graphDiff.Added...)
	for _, change := range graphDiff.Updated {
		basePackages = append(basePackages, change.Before)
		headPackages = append(headPackages, change.After)
	}

	baseGraph, err := focusedAuditGraph(basePackages)
	if err != nil {
		return nil, nil, err
	}
	headGraph, err := focusedAuditGraph(headPackages)
	if err != nil {
		return nil, nil, err
	}
	return baseGraph, headGraph, nil
}

func focusedAuditGraph(packages []*model.DependencyNode) (*model.Graph, error) {
	focused := model.NewWithCapacity(len(packages) + 1)
	seen := make(map[string]struct{}, len(packages))
	for _, pkg := range packages {
		if pkg == nil || pkg.NodeID() == "" {
			continue
		}
		seen[pkg.NodeID()] = struct{}{}
	}
	if len(seen) == 0 {
		return focused, nil
	}

	root, err := model.NewModuleNode(diffAuditRootManifest, model.Coordinates{
		Name: "bomly-diff-audit-root",
		Type: model.PackageTypeApplication,
	})
	if err != nil {
		return nil, fmt.Errorf("build diff audit root: %w", err)
	}
	if err := focused.AddNode(root); err != nil {
		return nil, err
	}

	for _, pkg := range packages {
		if pkg == nil || pkg.NodeID() == "" {
			continue
		}
		// Insert-or-keep is the shared helper's decision, not a hand-written
		// lookup: a package listed twice keeps the surviving node's records
		// instead of being silently dropped on the second sighting.
		if _, err := detectorkit.EnsureNode(focused, pkg.Clone()); err != nil {
			return nil, err
		}
		if err := focused.AddEdge(root.NodeID(), pkg.NodeID()); err != nil && !errors.Is(err, model.ErrSelfDependency) {
			return nil, err
		}
	}
	return focused, nil
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

// diffFindingKey identifies a finding independently of the package version, so
// a finding that survives a version bump (e.g. a CVE the upgrade does not
// remediate, or a license issue carried into the new version) classifies as
// persisted rather than as one introduced + one resolved.
//
// Vulnerabilities key on their advisory id (CVE/GHSA), which is already
// version-independent. License/package findings carry a per-version finding id
// (the id hashes the full PURL), so they instead key on the base PURL plus
// kind+source — each auditor emits at most one such finding per package, so
// this uniquely identifies "this package's license/policy status".
func diffFindingKey(finding model.Finding) string {
	base := model.PackageURLBase(finding.PackageRef)
	if base == "" {
		base = finding.PackageRef
	}
	discriminator := ""
	if finding.Kind == model.FindingKindVulnerability {
		discriminator = finding.VulnerabilityID
		if discriminator == "" {
			discriminator = finding.ID
		}
	}
	return fmt.Sprintf("%s|%s|%s|%s", finding.Kind, finding.Source, base, discriminator)
}
