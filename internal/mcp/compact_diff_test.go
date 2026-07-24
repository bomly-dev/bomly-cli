package mcp

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildCompactDiffBucketsAndRemediation(t *testing.T) {
	in := remediationFixture(t)
	baseRegistry := sdk.NewPackageRegistry()
	baseRegistry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/old-lib@0.9.0", Name: "old-lib", Version: "0.9.0", Ecosystem: sdk.EcosystemNPM},
		Vulnerabilities: []sdk.Vulnerability{{
			ID: "GHSA-resolved", Source: "osv", ParsedSeverity: sdk.SeverityHigh,
			FixState: sdk.FixStateFixed, FixedIn: "1.0.0",
		}},
	})

	run := DiffRunResult{
		Response: output.DiffResponse{
			Comparison: output.DiffComparison{Base: "main", Head: "feature"},
			Summary:    output.DiffSummary{ChangedManifestCount: 1, ChangedPackageCount: 2},
			Metadata:   output.Metadata{},
		},
		// lib-a's finding is introduced by head; deep's persists; the
		// old-lib finding only existed on base (resolved by this ref).
		Introduced: []sdk.Finding{in.Findings[0]},
		Persisted:  []sdk.Finding{in.Findings[1]},
		Resolved: []sdk.Finding{{
			ID: "GHSA-resolved", VulnerabilityID: "GHSA-resolved",
			Kind: sdk.FindingKindVulnerability, Severity: sdk.SeverityHigh,
			Source: "osv", Auditor: "vulnerability", PackageRef: "pkg:npm/old-lib@0.9.0",
		}},
		HeadGraph:     in.Graph,
		HeadRegistry:  in.Registry,
		BaseRegistry:  baseRegistry,
		HeadManifests: in.Manifests,
		AuditRan:      true,
	}

	compact := BuildCompactDiff(run)
	if compact.Summary.Introduced != 1 || compact.Summary.Persisted != 1 || compact.Summary.Resolved != 1 {
		t.Fatalf("summary counts wrong: %#v", compact.Summary)
	}
	if len(compact.SecurityDelta.Resolved) != 1 || compact.SecurityDelta.Resolved[0].VulnID != "GHSA-resolved" {
		t.Fatalf("resolved bucket wrong: %#v", compact.SecurityDelta.Resolved)
	}
	// Resolved findings join against the base registry for classification.
	if compact.SecurityDelta.Resolved[0].Classification != ClassificationFixAvailable {
		t.Fatalf("resolved classification should come from base registry: %#v", compact.SecurityDelta.Resolved[0])
	}
	// Remediations cover what is still open after merge: introduced + persisted.
	if len(compact.Remediations) != 3 {
		t.Fatalf("expected all 3 enriched vulnerabilities in remediation, got %#v", compact.Remediations)
	}
	direct := groupByAction(t, compact.Remediations, ActionDirectBump)
	if direct.TargetPackage.Name != "lib-a" {
		t.Fatalf("direct group wrong: %#v", direct.TargetPackage)
	}
	transitive := groupByAction(t, compact.Remediations, ActionTransitiveOverride)
	if transitive.TargetPackage.Name != "lib-b" {
		t.Fatalf("transitive group must target ancestor: %#v", transitive.TargetPackage)
	}
	if compact.SchemaVersion != CompactSchemaVersion || compact.Command != "diff" {
		t.Fatalf("header wrong: %#v", compact)
	}
}

func TestBuildCompactDiffEnrichedWithoutAuditReturnsHeadRemediation(t *testing.T) {
	in := remediationFixture(t)
	compact := BuildCompactDiff(DiffRunResult{
		Response: output.DiffResponse{
			Comparison: output.DiffComparison{Base: "main", Head: "feature"},
		},
		HeadGraph:     in.Graph,
		HeadRegistry:  in.Registry,
		HeadManifests: in.Manifests,
		EnrichRan:     true,
	})

	if len(compact.Remediations) != 3 {
		t.Fatalf("enriched diff remediation groups = %d, want 3: %#v",
			len(compact.Remediations), compact.Remediations)
	}
	if compact.Summary.AuditRan || !compact.Summary.EnrichRan {
		t.Fatalf("summary flags wrong: %#v", compact.Summary)
	}
	if len(compact.SecurityDelta.Introduced) != 0 ||
		len(compact.SecurityDelta.Resolved) != 0 ||
		len(compact.SecurityDelta.Persisted) != 0 {
		t.Fatalf("unaudited diff invented policy deltas: %#v", compact.SecurityDelta)
	}
}

func TestBuildCompactExplainAttachesRemediationAndDetail(t *testing.T) {
	in := remediationFixture(t)
	deepVulns := output.VulnerabilityRefsFromPackageVulnerabilities(mustRegistryVulns(t, in.Registry, "pkg:npm/@scope/deep@2.0.0"))
	run := ExplainRunResult{
		Response: output.ExplainResponse{
			Command: "explain",
			Query:   output.ExplainQuery{Name: "@scope/deep"},
			Targets: []output.ExplainTargetResponse{{
				PackageManager: sdk.PackageManagerNPM,
				Dependency: output.ExplainDependency{PackageRef: output.PackageRef{
					Name:            "@scope/deep",
					Version:         "2.0.0",
					Purl:            "pkg:npm/@scope/deep@2.0.0",
					Vulnerabilities: deepVulns,
				}},
				Paths: []output.DependencyPath{{
					Relationship: "transitive",
					Packages: []output.PackageRef{
						{Name: "app", Version: "1.0.0"},
						{Name: "lib-b", Version: "1.0.0"},
						{Name: "@scope/deep", Version: "2.0.0"},
					},
				}},
			}},
		},
		Findings:  in.Findings,
		Graph:     in.Graph,
		Registry:  in.Registry,
		Manifests: in.Manifests,
		AuditRan:  true,
	}

	compact := BuildCompactExplain("@scope/deep", run)
	if len(compact.Matches) != 1 {
		t.Fatalf("expected one match, got %#v", compact.Matches)
	}
	match := compact.Matches[0]
	// Full advisory detail rides on the match package — this is the
	// drill-down payload.
	if len(match.Package.Vulnerabilities) != 1 || match.Package.Vulnerabilities[0].ID != "GHSA-deep" {
		t.Fatalf("advisory detail missing: %#v", match.Package.Vulnerabilities)
	}
	if match.Direct == nil || *match.Direct {
		t.Fatalf("expected transitive, got %#v", match.Direct)
	}
	if len(match.Paths) != 1 || match.Paths[0][1] != "lib-b@1.0.0" {
		t.Fatalf("paths wrong: %#v", match.Paths)
	}
	// Remediation is scoped to the queried package only.
	if len(match.Remediations) != 1 || match.Remediations[0].Action != ActionTransitiveOverride {
		t.Fatalf("expected one transitive-override group, got %#v", match.Remediations)
	}
	if match.Remediations[0].TargetPackage.Name != "lib-b" {
		t.Fatalf("remediation must target the ancestor: %#v", match.Remediations[0].TargetPackage)
	}
	if match.ManifestPath != "" {
		t.Fatalf("fixture manifest has no purls; expected empty manifest path, got %q", match.ManifestPath)
	}
}

func TestBuildCompactExplainEnrichedWithoutAuditReturnsRemediation(t *testing.T) {
	in := remediationFixture(t)
	const purl = "pkg:npm/@scope/deep@2.0.0"
	run := ExplainRunResult{
		Response: output.ExplainResponse{
			Targets: []output.ExplainTargetResponse{{
				Dependency: output.ExplainDependency{PackageRef: output.PackageRef{
					Name:            "@scope/deep",
					Version:         "2.0.0",
					Purl:            purl,
					Vulnerabilities: output.VulnerabilityRefsFromPackageVulnerabilities(mustRegistryVulns(t, in.Registry, purl)),
				}},
			}},
		},
		Graph:     in.Graph,
		Registry:  in.Registry,
		Manifests: in.Manifests,
		EnrichRan: true,
	}

	compact := BuildCompactExplain("@scope/deep", run)
	if len(compact.Matches) != 1 || len(compact.Matches[0].Remediations) != 1 {
		t.Fatalf("enriched explain omitted remediation: %#v", compact.Matches)
	}
	if compact.Matches[0].Remediations[0].RecommendedVersion != "2.1.0" {
		t.Fatalf("recommended version did not use package context: %#v",
			compact.Matches[0].Remediations[0])
	}
}

func mustRegistryVulns(t *testing.T, registry *sdk.PackageRegistry, purl string) []sdk.Vulnerability {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil {
		t.Fatalf("package %s missing from registry", purl)
	}
	return pkg.Vulnerabilities
}
