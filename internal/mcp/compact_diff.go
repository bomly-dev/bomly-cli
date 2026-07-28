package mcp

import (
	"sort"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// diffHint tells agents how to drill into the delta.
const diffHint = "Introduced findings are new on head; resolved close when this ref merges; persisted remain after merge. Dependency transitions describe relationship, source, or registry-matching changes without treating them as version changes. Use bomly_explain (on the head checkout) for full advisory detail of one package."

// SecurityDelta buckets advisory findings by what merging head changes.
type SecurityDelta struct {
	Introduced []CompactFinding `json:"introduced,omitempty"`
	Resolved   []CompactFinding `json:"resolved,omitempty"`
	Persisted  []CompactFinding `json:"persisted,omitempty"`
}

// CompactDiffSummary counts manifest/package/finding deltas.
type CompactDiffSummary struct {
	ManifestsAdded       int  `json:"manifests_added,omitempty"`
	ManifestsChanged     int  `json:"manifests_changed,omitempty"`
	ManifestsRemoved     int  `json:"manifests_removed,omitempty"`
	PackagesAdded        int  `json:"packages_added,omitempty"`
	PackagesChanged      int  `json:"packages_changed,omitempty"`
	PackagesTransitioned int  `json:"packages_transitioned,omitempty"`
	PackagesRemoved      int  `json:"packages_removed,omitempty"`
	Introduced           int  `json:"introduced,omitempty"`
	Resolved             int  `json:"resolved,omitempty"`
	Persisted            int  `json:"persisted,omitempty"`
	EnrichRan            bool `json:"enrich_ran"`
	AuditRan             bool `json:"audit_ran"`
}

// CompactDependencyTransitionState is one side of a dependency occurrence
// metadata transition.
type CompactDependencyTransitionState struct {
	Relationship     string               `json:"relationship,omitempty"`
	Source           sdk.DependencySource `json:"source,omitempty"`
	RegistryEligible bool                 `json:"registry_eligible"`
}

// CompactDependencyTransition reports one same-identity metadata change
// without repeating licenses, vulnerabilities, locations, or other large
// package detail.
type CompactDependencyTransition struct {
	Package       PackageIdentity                  `json:"package"`
	ChangedFields []sdk.DependencyMetadataField    `json:"changed_fields"`
	Before        CompactDependencyTransitionState `json:"before"`
	After         CompactDependencyTransitionState `json:"after"`
}

// CompactDiffResponse is the bomly_diff tool result: the branch-aware
// security delta ("what does this ref fix vs base, what remains after
// merge") with integrated remediation context for what is still open.
type CompactDiffResponse struct {
	SchemaVersion string                        `json:"schema_version"`
	Command       string                        `json:"command"`
	Comparison    output.DiffComparison         `json:"comparison"`
	Summary       CompactDiffSummary            `json:"summary"`
	SecurityDelta SecurityDelta                 `json:"security_delta"`
	Transitions   []CompactDependencyTransition `json:"dependency_transitions,omitempty"`
	Remediations  []RemediationGroup            `json:"remediations,omitempty"`
	Informational []CompactFinding              `json:"informational,omitempty"`
	Diagnostics   []Diagnostic                  `json:"diagnostics,omitempty"`
	Truncation    *TruncationInfo               `json:"truncation,omitempty"`
	Hint          string                        `json:"hint,omitempty"`
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
			ManifestsAdded:       run.Response.Summary.AddedManifestCount,
			ManifestsChanged:     run.Response.Summary.ChangedManifestCount,
			ManifestsRemoved:     run.Response.Summary.RemovedManifestCount,
			PackagesAdded:        run.Response.Summary.AddedPackageCount,
			PackagesChanged:      run.Response.Summary.ChangedPackageCount,
			PackagesTransitioned: run.Response.Summary.TransitionedPackageCount,
			PackagesRemoved:      run.Response.Summary.RemovedPackageCount,
			Introduced:           len(run.Introduced),
			Resolved:             len(run.Resolved),
			Persisted:            len(run.Persisted),
			AuditRan:             run.AuditRan,
			EnrichRan:            run.EnrichRan,
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
	response.Transitions = compactDependencyTransitions(run.Response.Results.Dependencies.Transitions, trunc)
	response.SecurityDelta.Introduced = compactFindingList(run.Introduced, headInput, trunc)
	response.SecurityDelta.Persisted = compactFindingList(run.Persisted, headInput, trunc)
	response.SecurityDelta.Resolved = compactFindingList(run.Resolved, baseInput, trunc)

	// Remediation context covers every enriched head vulnerability. Audit
	// findings overlay policy status for findings that remain open after merge.
	open := append(append([]sdk.Finding{}, run.Introduced...), run.Persisted...)
	headInput.Findings = remediationFindings(run.HeadRegistry, open, run.AuditRan)
	remediation := buildRemediations(headInput)
	response.Remediations = remediation.Remediations
	response.Informational = remediation.Informational
	mergeTruncation(trunc, remediation.Truncation)

	if trunc.OmittedFindings > 0 || trunc.OmittedGroups > 0 || trunc.OmittedPackages > 0 || trunc.OmittedPaths > 0 || trunc.OmittedTransitions > 0 {
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
	target.OmittedPackages += source.OmittedPackages
	target.OmittedPaths += source.OmittedPaths
	target.OmittedTransitions += source.OmittedTransitions
}

func compactDependencyTransitions(transitions []output.DiffDependencyTransition, trunc *TruncationInfo) []CompactDependencyTransition {
	if len(transitions) == 0 {
		return nil
	}
	sorted := append([]output.DiffDependencyTransition(nil), transitions...)
	sort.Slice(sorted, func(i, j int) bool {
		return compactDependencyTransitionSortKey(sorted[i]) < compactDependencyTransitionSortKey(sorted[j])
	})
	limit := len(sorted)
	if limit > maxDependencyTransitions {
		trunc.OmittedTransitions += limit - maxDependencyTransitions
		limit = maxDependencyTransitions
	}
	out := make([]CompactDependencyTransition, 0, limit)
	for _, transition := range sorted[:limit] {
		pkg := transition.After
		out = append(out, CompactDependencyTransition{
			Package: PackageIdentity{
				Name:    pkg.Name,
				Version: pkg.Version,
				Purl:    pkg.Purl,
			},
			ChangedFields: append([]sdk.DependencyMetadataField(nil), transition.ChangedFields...),
			Before: CompactDependencyTransitionState{
				Relationship:     transition.Before.Relationship,
				Source:           transition.Before.Source,
				RegistryEligible: transition.Before.RegistryEligible,
			},
			After: CompactDependencyTransitionState{
				Relationship:     transition.After.Relationship,
				Source:           transition.After.Source,
				RegistryEligible: transition.After.RegistryEligible,
			},
		})
	}
	return out
}

func compactDependencyTransitionSortKey(transition output.DiffDependencyTransition) string {
	fields := make([]string, 0, len(transition.ChangedFields))
	for _, field := range transition.ChangedFields {
		fields = append(fields, string(field))
	}
	return strings.Join([]string{
		transition.After.Purl,
		transition.After.Name,
		transition.After.ID,
		transition.Before.Relationship,
		transition.After.Relationship,
		string(transition.Before.Source),
		string(transition.After.Source),
		strconv.FormatBool(transition.Before.RegistryEligible),
		strconv.FormatBool(transition.After.RegistryEligible),
		strings.Join(fields, ","),
	}, "\x00")
}
