package mcp

import (
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// diffHint tells agents how to drill into the delta.
const diffHint = "Introduced findings are new on head; resolved close when this ref merges; persisted remain after merge. Use bomly_explain (on the head checkout) for full advisory detail of one package."

// SecurityDelta buckets advisory findings by what merging head changes.
type SecurityDelta struct {
	Introduced []CompactFinding `json:"introduced,omitempty"`
	Resolved   []CompactFinding `json:"resolved,omitempty"`
	Persisted  []CompactFinding `json:"persisted,omitempty"`
}

// CompactDiffSummary counts manifest/package/finding deltas.
type CompactDiffSummary struct {
	ManifestsAdded   int  `json:"manifests_added,omitempty"`
	ManifestsChanged int  `json:"manifests_changed,omitempty"`
	ManifestsRemoved int  `json:"manifests_removed,omitempty"`
	PackagesAdded    int  `json:"packages_added,omitempty"`
	PackagesChanged  int  `json:"packages_changed,omitempty"`
	PackagesRemoved  int  `json:"packages_removed,omitempty"`
	Introduced       int  `json:"introduced,omitempty"`
	Resolved         int  `json:"resolved,omitempty"`
	Persisted        int  `json:"persisted,omitempty"`
	EnrichRan        bool `json:"enrich_ran"`
	AuditRan         bool `json:"audit_ran"`
}

// CompactDiffResponse is the bomly_diff tool result: the branch-aware
// security delta ("what does this ref fix vs base, what remains after
// merge") with integrated remediation context for what is still open.
type CompactDiffResponse struct {
	SchemaVersion string                `json:"schema_version"`
	Command       string                `json:"command"`
	Comparison    output.DiffComparison `json:"comparison"`
	Summary       CompactDiffSummary    `json:"summary"`
	SecurityDelta SecurityDelta         `json:"security_delta"`
	Remediations  []RemediationGroup    `json:"remediations,omitempty"`
	Diagnostics   []Diagnostic          `json:"diagnostics,omitempty"`
	Truncation    *TruncationInfo       `json:"truncation,omitempty"`
	Hint          string                `json:"hint,omitempty"`
}

// BuildCompactDiff projects a diff run into the agent-facing compact
// response. Introduced and persisted findings — the ones still open after
// merge — get remediation groups built against the head state; resolved
// findings are listed against the base registry (they no longer exist on
// head).
func BuildCompactDiff(run DiffRunResult) CompactDiffResponse {
	response := CompactDiffResponse{
		SchemaVersion: CompactSchemaVersion,
		Command:       "diff",
		Comparison:    run.Response.Comparison,
		Summary: CompactDiffSummary{
			ManifestsAdded:   run.Response.Summary.AddedManifestCount,
			ManifestsChanged: run.Response.Summary.ChangedManifestCount,
			ManifestsRemoved: run.Response.Summary.RemovedManifestCount,
			PackagesAdded:    run.Response.Summary.AddedPackageCount,
			PackagesChanged:  run.Response.Summary.ChangedPackageCount,
			PackagesRemoved:  run.Response.Summary.RemovedPackageCount,
			Introduced:       len(run.Introduced),
			Resolved:         len(run.Resolved),
			Persisted:        len(run.Persisted),
			AuditRan:         run.AuditRan,
			EnrichRan:        run.HeadRegistry != nil && run.HeadRegistry.Len() > 0,
		},
		Diagnostics: capDiagnostics(run.Diagnostics),
		Hint:        diffHint,
	}

	includeReachability := run.Response.Metadata.ReachabilityEnabled
	headInput := remediationInput{
		Graph:               run.HeadGraph,
		Registry:            run.HeadRegistry,
		Manifests:           run.HeadManifests,
		IncludeReachability: includeReachability,
	}
	baseInput := remediationInput{
		Registry:            run.BaseRegistry,
		IncludeReachability: includeReachability,
	}

	trunc := &TruncationInfo{}
	response.SecurityDelta.Introduced = compactFindingList(run.Introduced, headInput, trunc)
	response.SecurityDelta.Persisted = compactFindingList(run.Persisted, headInput, trunc)
	response.SecurityDelta.Resolved = compactFindingList(run.Resolved, baseInput, trunc)

	// Remediation context covers everything still open after merge.
	open := append(append([]sdk.Finding{}, run.Introduced...), run.Persisted...)
	headInput.Findings = open
	remediation := buildRemediations(headInput)
	response.Remediations = remediation.Remediations
	mergeTruncation(trunc, remediation.Truncation)

	if trunc.OmittedFindings > 0 || trunc.OmittedGroups > 0 {
		trunc.Truncated = true
		trunc.Note = "response was capped; diff a narrower path or use bomly_explain per package for the rest"
		response.Truncation = trunc
	}
	return response
}

// compactFindingList converts one delta bucket, capped at maxInformational
// entries per bucket.
func compactFindingList(findings []sdk.Finding, in remediationInput, trunc *TruncationInfo) []CompactFinding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]CompactFinding, 0, len(findings))
	for _, f := range findings {
		if len(out) >= maxInformational {
			trunc.OmittedFindings++
			continue
		}
		vuln := lookupFindingVulnerability(in.Registry, f)
		compact, _ := buildCompactFinding(f, vuln, in)
		out = append(out, compact)
	}
	sortCompactFindings(out)
	return out
}

func mergeTruncation(target, source *TruncationInfo) {
	if source == nil {
		return
	}
	target.OmittedFindings += source.OmittedFindings
	target.OmittedGroups += source.OmittedGroups
}
