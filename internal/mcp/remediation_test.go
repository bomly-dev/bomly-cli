package mcp

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
)

// remediationFixture builds a small realistic scan state:
//
//	app@1.0.0 (root)
//	├── lib-a@1.0.0            vulnerable, fixed in 1.2.0   → direct-bump
//	├── lib-b@1.0.0
//	│   └── @scope/deep@2.0.0  vulnerable (KEV), fixed 2.1.0 → transitive-override via lib-b
//	└── legacy@0.1.0           vulnerable, no fix            → no-fix-upstream
func remediationFixture(t *testing.T) remediationInput {
	t.Helper()
	g := model.New()
	nodes := []*model.DependencyNode{
		testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "app", Version: "1.0.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/app@1.0.0"}}),
		testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "lib-a", Version: "1.0.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/lib-a@1.0.0"}}),
		testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "lib-b", Version: "1.0.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/lib-b@1.0.0"}}),
		testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Org: "scope", Name: "deep", Version: "2.0.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/@scope/deep@2.0.0"}}),
		testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "legacy", Version: "0.1.0", Ecosystem: model.EcosystemNPM, PURL: "pkg:npm/legacy@0.1.0"}}),
	}
	for _, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("add node %s: %v", node.NodeID(), err)
		}
	}
	edges := [][2]string{
		{nodes[0].NodeID(), nodes[1].NodeID()},
		{nodes[0].NodeID(), nodes[2].NodeID()},
		{nodes[2].NodeID(), nodes[3].NodeID()},
		{nodes[0].NodeID(), nodes[4].NodeID()},
	}
	for _, edge := range edges {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %v: %v", edge, err)
		}
	}

	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: "pkg:npm/lib-a@1.0.0", Name: "lib-a", Version: "1.0.0", Ecosystem: model.EcosystemNPM},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
			Suggestions: []model.PackageRemediationSuggestion{{
				AffectedDependencyRefs:       []string{nodes[1].NodeID()},
				SuggestedActionDependencyRef: nodes[1].NodeID(),
				ManifestPath:                 "package.json",
				Action:                       model.RemediationActionDirectBump,
			}},
		},
		Vulnerabilities: []model.Vulnerability{{
			ID: "GHSA-liba", Aliases: []string{"CVE-2026-1111"}, Source: "osv",
			ParsedSeverity: model.SeverityHigh, FixState: model.FixStateFixed, FixedIn: "1.2.0",
		}},
	})
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: "pkg:npm/@scope/deep@2.0.0", Org: "scope", Name: "deep", Version: "2.0.0", Ecosystem: model.EcosystemNPM},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "2.1.0",
			Suggestions: []model.PackageRemediationSuggestion{{
				AffectedDependencyRefs:       []string{nodes[3].NodeID()},
				SuggestedActionDependencyRef: nodes[2].NodeID(),
				ManifestPath:                 "package.json",
				Action:                       model.RemediationActionTransitiveOverride,
				OverrideAdvice:               `add "overrides": {"@scope/deep": "2.1.0"} to package.json and run npm install`,
			}},
		},
		Vulnerabilities: []model.Vulnerability{{
			ID: "GHSA-deep", Source: "osv",
			ParsedSeverity: model.SeverityMedium, FixState: model.FixStateFixed, FixedIn: "2.1.0",
			KEVExploited: true,
			EPSS:         []model.EPSSScore{{EPSS: 0.92}},
		}},
	})
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: "pkg:npm/legacy@0.1.0", Name: "legacy", Version: "0.1.0", Ecosystem: model.EcosystemNPM},
		Remediation: &model.PackageRemediation{
			Status: model.PackageRemediationUnavailable,
			Suggestions: []model.PackageRemediationSuggestion{{
				AffectedDependencyRefs:       []string{nodes[4].NodeID()},
				SuggestedActionDependencyRef: nodes[4].NodeID(),
				ManifestPath:                 "package.json",
				Action:                       model.RemediationActionNoFixUpstream,
			}},
		},
		Vulnerabilities: []model.Vulnerability{{
			ID: "GHSA-legacy", Source: "osv",
			ParsedSeverity: model.SeverityCritical, FixState: model.FixStateNotFixed,
		}},
	})

	manifest := output.ScanManifest{
		Path:           "package.json",
		PackageManager: model.PackageManagerNPM,
		Dependencies: []output.ScanDependency{
			{ID: nodes[0].NodeID(), Name: "app", Version: "1.0.0"},
			{ID: nodes[1].NodeID(), Name: "lib-a", Version: "1.0.0"},
			{ID: nodes[2].NodeID(), Name: "lib-b", Version: "1.0.0"},
			{ID: nodes[3].NodeID(), Name: "@scope/deep", Version: "2.0.0"},
			{ID: nodes[4].NodeID(), Name: "legacy", Version: "0.1.0"},
		},
	}

	findings := []model.Finding{
		{
			ID: "GHSA-liba", VulnerabilityID: "GHSA-liba", Kind: model.FindingKindVulnerability,
			Severity: model.SeverityHigh, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/lib-a@1.0.0", DependencyRefs: []string{nodes[1].NodeID()},
		},
		{
			ID: "GHSA-deep", VulnerabilityID: "GHSA-deep", Kind: model.FindingKindVulnerability,
			Severity: model.SeverityMedium, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/@scope/deep@2.0.0", DependencyRefs: []string{nodes[3].NodeID()},
		},
		{
			ID: "GHSA-legacy", VulnerabilityID: "GHSA-legacy", Kind: model.FindingKindVulnerability,
			Severity: model.SeverityCritical, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/legacy@0.1.0", DependencyRefs: []string{nodes[4].NodeID()},
		},
		{
			ID: "license:unknown-license:lib-a@1.0.0", Kind: model.FindingKindLicense,
			Severity: "n/a", Source: "license", Auditor: "license",
			RuleID:       "unknown-license",
			PolicyStatus: model.FindingPolicyStatusWarn,
			PackageRef:   "pkg:npm/lib-a@1.0.0", DependencyRefs: []string{nodes[1].NodeID()},
		},
	}

	return remediationInput{
		Findings:  findings,
		Graph:     g,
		Registry:  registry,
		Manifests: []output.ScanManifest{manifest},
	}
}

func groupByAction(t *testing.T, groups []RemediationGroup, action string) RemediationGroup {
	t.Helper()
	for _, group := range groups {
		if group.Action == action {
			return group
		}
	}
	t.Fatalf("no group with action %q in %#v", action, groups)
	return RemediationGroup{}
}

func TestBuildRemediationsGroupsAndActions(t *testing.T) {
	out := buildRemediations(remediationFixture(t))

	if len(out.Remediations) != 3 {
		t.Fatalf("expected 3 remediation groups, got %d: %#v", len(out.Remediations), out.Remediations)
	}
	if out.Truncation != nil {
		t.Fatalf("unexpected truncation: %#v", out.Truncation)
	}

	direct := groupByAction(t, out.Remediations, ActionDirectBump)
	if direct.TargetPackage.Name != "lib-a" || direct.RecommendedVersion != "1.2.0" {
		t.Fatalf("direct-bump group wrong: %#v", direct)
	}
	if direct.ManifestPath != "package.json" || direct.PackageManager != "npm" {
		t.Fatalf("direct-bump manifest wrong: %#v", direct)
	}
	if len(direct.Fixes) != 1 || direct.Fixes[0].Classification != ClassificationFixAvailable {
		t.Fatalf("direct-bump fixes wrong: %#v", direct.Fixes)
	}

	transitive := groupByAction(t, out.Remediations, ActionTransitiveOverride)
	if transitive.TargetPackage.Name != "lib-b" {
		t.Fatalf("transitive group must target the direct ancestor lib-b, got %#v", transitive.TargetPackage)
	}
	fix := transitive.Fixes[0]
	if fix.Package.Name != "@scope/deep" || fix.Package.Org != "scope" {
		t.Fatalf("scoped identity mangled in compact finding: %#v", fix.Package)
	}
	if fix.Direct == nil || *fix.Direct {
		t.Fatalf("deep should be transitive: %#v", fix.Direct)
	}
	wantPath := []string{"app@1.0.0", "lib-b@1.0.0", "@scope/deep@2.0.0"}
	if len(fix.ShortestPath) != len(wantPath) {
		t.Fatalf("shortest path = %#v, want %#v", fix.ShortestPath, wantPath)
	}
	for idx := range wantPath {
		if fix.ShortestPath[idx] != wantPath[idx] {
			t.Fatalf("shortest path = %#v, want %#v", fix.ShortestPath, wantPath)
		}
	}

	noFix := groupByAction(t, out.Remediations, ActionNoFixUpstream)
	if noFix.Fixes[0].Classification != ClassificationNoFixUpstream {
		t.Fatalf("no-fix classification wrong: %#v", noFix.Fixes[0])
	}

	// The warning-status license finding is informational.
	if len(out.Informational) != 1 || out.Informational[0].Kind != string(model.FindingKindLicense) {
		t.Fatalf("informational bucket wrong: %#v", out.Informational)
	}
	if out.Informational[0].Classification != ClassificationPolicyOnly {
		t.Fatalf("license finding classification = %q", out.Informational[0].Classification)
	}
	if out.Informational[0].RuleID != "unknown-license" {
		t.Fatalf("license finding rule ID = %q", out.Informational[0].RuleID)
	}
}

func TestBuildRemediationsRanksKEVFirst(t *testing.T) {
	out := buildRemediations(remediationFixture(t))
	// GHSA-deep is medium severity but KEV-exploited — it must outrank the
	// critical no-fix and the high direct-bump groups.
	if out.Remediations[0].Fixes[0].VulnID != "GHSA-deep" {
		t.Fatalf("KEV group not ranked first: %#v", out.Remediations[0])
	}
	if !out.Remediations[0].Fixes[0].KEV {
		t.Fatal("KEV flag missing on compact finding")
	}
}

func TestBuildRemediationsSameFixClosesMultipleFindings(t *testing.T) {
	in := remediationFixture(t)
	// Second advisory on lib-a with a higher fixed version: one direct bump
	// closes both, and the recommended version covers both.
	if pkg, ok := in.Registry.Get("pkg:npm/lib-a@1.0.0"); ok {
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{
			ID: "GHSA-liba2", Source: "osv",
			ParsedSeverity: model.SeverityLow, FixState: model.FixStateFixed, FixedIn: "1.3.0",
		})
		pkg.Remediation = &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.3.0",
			Suggestions: []model.PackageRemediationSuggestion{{
				AffectedDependencyRefs:       append([]string(nil), in.Findings[0].DependencyRefs...),
				SuggestedActionDependencyRef: in.Findings[0].DependencyRefs[0],
				ManifestPath:                 "package.json",
				Action:                       model.RemediationActionDirectBump,
			}},
		}
	}
	in.Findings = append(in.Findings, model.Finding{
		ID: "GHSA-liba2", VulnerabilityID: "GHSA-liba2", Kind: model.FindingKindVulnerability,
		Severity: model.SeverityLow, Source: "osv", Auditor: "vulnerability",
		PackageRef: "pkg:npm/lib-a@1.0.0", DependencyRefs: in.Findings[0].DependencyRefs,
	})

	out := buildRemediations(in)
	direct := groupByAction(t, out.Remediations, ActionDirectBump)
	if len(direct.Fixes) != 2 {
		t.Fatalf("expected one group closing both lib-a findings, got %#v", direct)
	}
	if direct.RecommendedVersion != "1.3.0" {
		t.Fatalf("recommended version must satisfy all grouped findings, got %q", direct.RecommendedVersion)
	}
}

func TestBuildRemediationsTruncatesWithCounters(t *testing.T) {
	in := remediationFixture(t)
	// Add one no-fix finding per synthetic package to exceed the group cap.
	for i := range maxRemediationGroups + 10 {
		purl := fmt.Sprintf("pkg:npm/synth-%03d@1.0.0", i)
		in.Registry.Add(&model.Package{
			Coordinates: model.Coordinates{PURL: purl, Name: fmt.Sprintf("synth-%03d", i), Version: "1.0.0", Ecosystem: model.EcosystemNPM},
			Remediation: &model.PackageRemediation{
				Status: model.PackageRemediationUnavailable,
				Suggestions: []model.PackageRemediationSuggestion{{
					Action: model.RemediationActionNoFixUpstream,
				}},
			},
			Vulnerabilities: []model.Vulnerability{{
				ID: fmt.Sprintf("GHSA-synth-%03d", i), Source: "osv",
				ParsedSeverity: model.SeverityLow, FixState: model.FixStateNotFixed,
			}},
		})
		in.Findings = append(in.Findings, model.Finding{
			ID:              fmt.Sprintf("GHSA-synth-%03d", i),
			VulnerabilityID: fmt.Sprintf("GHSA-synth-%03d", i),
			Kind:            model.FindingKindVulnerability,
			Severity:        model.SeverityLow, Source: "osv", Auditor: "vulnerability",
			PackageRef: purl,
		})
	}
	out := buildRemediations(in)
	if len(out.Remediations) != maxRemediationGroups {
		t.Fatalf("group cap not applied: got %d groups", len(out.Remediations))
	}
	if out.Truncation == nil || !out.Truncation.Truncated || out.Truncation.OmittedGroups == 0 {
		t.Fatalf("truncation counters missing: %#v", out.Truncation)
	}
}

func TestBuildRemediationsCountsDistinctOmissionsAcrossSuggestions(t *testing.T) {
	const purl = "pkg:npm/shared@1.0.0"
	registry := model.NewPackageRegistry()
	pkg := &model.Package{
		Coordinates: model.Coordinates{
			PURL: purl, Name: "shared", Version: "1.0.0", Ecosystem: model.EcosystemNPM,
		},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.1.0",
			Suggestions: []model.PackageRemediationSuggestion{
				{Action: model.RemediationActionDirectBump, ManifestPath: "package.json"},
				{Action: model.RemediationActionDirectBump, ManifestPath: "packages/web/package.json"},
			},
		},
	}
	var findings []model.Finding
	for idx := range maxFindingsPerGroup + 5 {
		id := fmt.Sprintf("GHSA-shared-%02d", idx)
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{
			ID: id, ParsedSeverity: model.SeverityHigh, FixedIn: "1.1.0",
		})
		findings = append(findings, model.Finding{
			ID: id, VulnerabilityID: id, Kind: model.FindingKindVulnerability,
			Severity: model.SeverityHigh, PackageRef: purl,
		})
	}
	registry.Add(pkg)

	out := buildRemediations(remediationInput{Findings: findings, Registry: registry})
	if len(out.Remediations) != 2 {
		t.Fatalf("groups = %d, want 2", len(out.Remediations))
	}
	if out.Truncation == nil || out.Truncation.OmittedFindings != 5 {
		t.Fatalf("distinct omitted findings = %#v, want 5", out.Truncation)
	}

	compact := BuildCompactScan(ScanRunResult{
		Response:  output.ScanResponse{Packages: output.PackagesFromRegistry(registry)},
		Graph:     nil,
		Registry:  registry,
		EnrichRan: true,
	})
	if compact.Summary.Actionable != maxFindingsPerGroup {
		t.Fatalf("actionable = %d, want %d distinct returned findings",
			compact.Summary.Actionable, maxFindingsPerGroup)
	}
	if compact.Summary.FindingsBySeverity[string(model.SeverityHigh)] != maxFindingsPerGroup {
		t.Fatalf("severity counts double-counted suggestions: %#v", compact.Summary.FindingsBySeverity)
	}
}

func TestBuildRemediationsDoesNotOmitVisibleFindingsAtGroupCap(t *testing.T) {
	const purl = "pkg:npm/shared@1.0.0"
	suggestions := make([]model.PackageRemediationSuggestion, maxRemediationGroups+3)
	for idx := range suggestions {
		suggestions[idx] = model.PackageRemediationSuggestion{
			Action:       model.RemediationActionDirectBump,
			ManifestPath: fmt.Sprintf("workspace-%02d/package.json", idx),
		}
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{
			PURL: purl, Name: "shared", Version: "1.0.0", Ecosystem: model.EcosystemNPM,
		},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.1.0",
			Suggestions:        suggestions,
		},
		Vulnerabilities: []model.Vulnerability{{
			ID: "GHSA-shared", ParsedSeverity: model.SeverityHigh, FixedIn: "1.1.0",
		}},
	})
	out := buildRemediations(remediationInput{
		Registry: registry,
		Findings: []model.Finding{{
			ID: "GHSA-shared", VulnerabilityID: "GHSA-shared",
			Kind: model.FindingKindVulnerability, Severity: model.SeverityHigh, PackageRef: purl,
		}},
	})
	if out.Truncation == nil || out.Truncation.OmittedGroups != 3 ||
		out.Truncation.OmittedFindings != 0 {
		t.Fatalf("truncation = %#v, want 3 groups and no hidden findings", out.Truncation)
	}
}

func TestBuildRemediationsCapsLeftoverPackagesDeterministically(t *testing.T) {
	findings := make([]model.Finding, maxInformational+10)
	for idx := range findings {
		id := fmt.Sprintf("GHSA-leftover-%03d", idx)
		findings[idx] = model.Finding{
			ID: id, VulnerabilityID: id, Kind: model.FindingKindVulnerability,
			Severity:   model.SeverityLow,
			PackageRef: fmt.Sprintf("pkg:npm/leftover-%03d@1.0.0", idx),
		}
	}
	for run := range 10 {
		out := buildRemediations(remediationInput{
			Findings: findings,
			Registry: model.NewPackageRegistry(),
		})
		if len(out.Informational) != maxInformational {
			t.Fatalf("run %d informational = %d", run, len(out.Informational))
		}
		for idx, finding := range out.Informational {
			want := fmt.Sprintf("GHSA-leftover-%03d", idx)
			if finding.VulnID != want {
				t.Fatalf("run %d informational[%d] = %q, want %q",
					run, idx, finding.VulnID, want)
			}
		}
	}
}

func TestShortestPathBoundsLongChains(t *testing.T) {
	g := model.New()
	var previous string
	for i := range 10 {
		node := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
			Name: fmt.Sprintf("chain-%d", i), Version: "1.0.0", Ecosystem: model.EcosystemNPM,
			PURL: fmt.Sprintf("pkg:npm/chain-%d@1.0.0", i),
		}})
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
		if previous != "" {
			if err := g.AddEdge(previous, node.NodeID()); err != nil {
				t.Fatal(err)
			}
		}
		previous = node.NodeID()
	}
	path := shortestPathToRoot(g, previous)
	if len(path) != 10 {
		t.Fatalf("expected full 10-node chain, got %d", len(path))
	}
	labels := pathLabels(path)
	if len(labels) != maxPathNodes+1 {
		t.Fatalf("expected capped labels (%d), got %d: %#v", maxPathNodes+1, len(labels), labels)
	}
	if labels[maxPathNodes-1] != "… (+4 more hops)" {
		t.Fatalf("expected hop marker, got %#v", labels)
	}
	if labels[len(labels)-1] != "chain-9@1.0.0" {
		t.Fatalf("target must close the path, got %#v", labels)
	}
}

func TestCompactScanSizeStaysUnderBudget(t *testing.T) {
	in := remediationFixture(t)
	// Grow the fixture to ~15 vulnerable packages — the scale from issue
	// #245 — and assert the serialized compact response stays a few KB.
	for i := range 12 {
		purl := fmt.Sprintf("pkg:npm/extra-%02d@1.0.0", i)
		in.Registry.Add(&model.Package{
			Coordinates: model.Coordinates{PURL: purl, Name: fmt.Sprintf("extra-%02d", i), Version: "1.0.0", Ecosystem: model.EcosystemNPM},
			Remediation: &model.PackageRemediation{Status: model.PackageRemediationComplete, RecommendedVersion: "1.1.0"},
			Vulnerabilities: []model.Vulnerability{{
				ID: fmt.Sprintf("GHSA-extra-%02d", i), Source: "osv",
				ParsedSeverity: model.SeverityHigh, FixState: model.FixStateFixed, FixedIn: "1.1.0",
				Details:    "a very long advisory description that must never appear in the compact response because it belongs to the drill-down path only",
				References: []model.Reference{{URL: "https://example.com/advisory"}},
			}},
		})
		in.Findings = append(in.Findings, model.Finding{
			ID:              fmt.Sprintf("GHSA-extra-%02d", i),
			VulnerabilityID: fmt.Sprintf("GHSA-extra-%02d", i),
			Kind:            model.FindingKindVulnerability,
			Severity:        model.SeverityHigh, Source: "osv", Auditor: "vulnerability",
			PackageRef: purl,
		})
	}
	run := ScanRunResult{
		Response: output.ScanResponse{
			Manifests: in.Manifests,
			Packages:  output.PackagesFromRegistry(in.Registry),
		},
		Findings:  in.Findings,
		Graph:     in.Graph,
		Registry:  in.Registry,
		EnrichRan: true,
		AuditRan:  true,
	}
	compact := BuildCompactScan(run)
	raw, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 8 * 1024
	if len(raw) > budget {
		t.Fatalf("compact scan response is %d bytes, budget %d:\n%s", len(raw), budget, raw)
	}
	if len(compact.Remediations) == 0 {
		t.Fatal("expected remediation groups")
	}
	for _, group := range compact.Remediations {
		for _, fix := range group.Fixes {
			if fix.Title == "" && fix.VulnID == "" {
				t.Fatalf("empty fix entry: %#v", group)
			}
		}
	}
}

func TestBuildCompactScanWithoutAuditReturnsInventory(t *testing.T) {
	in := remediationFixture(t)
	run := ScanRunResult{
		Response: output.ScanResponse{Manifests: in.Manifests},
	}
	compact := BuildCompactScan(run)
	if compact.Summary.AuditRan || compact.Summary.EnrichRan {
		t.Fatalf("summary flags wrong: %#v", compact.Summary)
	}
	if len(compact.Packages) != 5 {
		t.Fatalf("expected 5 inventory entries, got %#v", compact.Packages)
	}
	if len(compact.Remediations) != 0 {
		t.Fatalf("no remediations expected without audit: %#v", compact.Remediations)
	}
	if compact.Summary.TotalPackages != 5 {
		t.Fatalf("total packages = %d, want 5", compact.Summary.TotalPackages)
	}
}

func TestBuildCompactScanEnrichedWithoutAuditReturnsRemediation(t *testing.T) {
	in := remediationFixture(t)
	run := ScanRunResult{
		Response: output.ScanResponse{
			Manifests: in.Manifests,
			Packages:  output.PackagesFromRegistry(in.Registry),
		},
		Graph:     in.Graph,
		Registry:  in.Registry,
		EnrichRan: true,
	}

	compact := BuildCompactScan(run)
	if len(compact.Remediations) != 3 {
		t.Fatalf("enriched scan remediation groups = %d, want 3: %#v",
			len(compact.Remediations), compact.Remediations)
	}
	if len(compact.Packages) != 0 {
		t.Fatalf("enriched scan returned plain inventory instead of remediation: %#v", compact.Packages)
	}
	if !compact.Summary.EnrichRan || compact.Summary.AuditRan {
		t.Fatalf("summary flags wrong: %#v", compact.Summary)
	}
}

func TestBuildCompactScanEnrichedCleanProjectReturnsInventory(t *testing.T) {
	in := remediationFixture(t)
	run := ScanRunResult{
		Response:  output.ScanResponse{Manifests: in.Manifests},
		Registry:  model.NewPackageRegistry(),
		EnrichRan: true,
	}

	compact := BuildCompactScan(run)
	if len(compact.Packages) != 5 {
		t.Fatalf("clean enriched scan inventory = %#v, want 5 packages", compact.Packages)
	}
	if len(compact.Remediations) != 0 || len(compact.Informational) != 0 {
		t.Fatalf("clean enriched scan returned findings: %#v", compact)
	}
	if !compact.Summary.EnrichRan || compact.Summary.AuditRan ||
		compact.Summary.VulnerablePackages != 0 || compact.Summary.CleanPackages != 5 {
		t.Fatalf("clean enriched summary = %#v", compact.Summary)
	}
}

func TestRemediationFindingsOverlayAuditWithoutFilteringEnrichment(t *testing.T) {
	in := remediationFixture(t)
	audit := in.Findings[0].Clone()
	audit.VulnerabilityID = "cve-2026-1111"
	audit.PolicyStatus = model.FindingPolicyStatusWarn
	audit.Reasons = []string{"accepted during rollout"}

	findings := remediationFindings(in.Registry, []model.Finding{audit}, true)
	if len(findings) != 3 {
		t.Fatalf("joined findings = %d, want all 3 enriched vulnerabilities: %#v", len(findings), findings)
	}
	var overlaid *model.Finding
	for idx := range findings {
		if findings[idx].PackageRef == audit.PackageRef {
			overlaid = &findings[idx]
			break
		}
	}
	if overlaid == nil || overlaid.PolicyStatus != model.FindingPolicyStatusWarn ||
		len(overlaid.Reasons) != 1 {
		t.Fatalf("audit policy was not overlaid: %#v", overlaid)
	}
	for idx := range findings {
		if findings[idx].PackageRef != audit.PackageRef &&
			findings[idx].PolicyStatus != model.FindingPolicyStatusSuppressed {
			t.Fatalf("vulnerability omitted by audit was not suppressed: %#v", findings[idx])
		}
	}
	overlaid.Reasons[0] = "changed"
	if audit.Reasons[0] != "accepted during rollout" {
		t.Fatalf("overlay mutated audit input: %#v", audit)
	}
}

func TestClassifyFindingMatrix(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		vuln *model.Vulnerability
		want string
	}{
		{"license", model.Finding{Kind: model.FindingKindLicense}, nil, ClassificationPolicyOnly},
		{"package", model.Finding{Kind: model.FindingKindPackage}, nil, ClassificationPolicyOnly},
		{"no advisory data", model.Finding{Kind: model.FindingKindVulnerability}, nil, ClassificationUnknown},
		{"fixed state", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixState: model.FixStateFixed}, ClassificationFixAvailable},
		{"fixed-in only", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixedIn: "1.2.3"}, ClassificationFixAvailable},
		{"fixed versions", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixedVersions: []string{"2.0.0"}}, ClassificationFixAvailable},
		{"fix available list", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixAvailable: []model.FixAvailable{{Version: "2.0.0"}}}, ClassificationFixAvailable},
		{"wont fix", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixState: model.FixStateWontFix}, ClassificationWontFix},
		{"not fixed", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixState: model.FixStateNotFixed}, ClassificationNoFixUpstream},
		{"unknown state", model.Finding{Kind: model.FindingKindVulnerability}, &model.Vulnerability{FixState: model.FixStateUnknown}, ClassificationUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFinding(tc.f, tc.vuln); got != tc.want {
				t.Errorf("classifyFinding() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWarnWithFixAvailableStaysInformational(t *testing.T) {
	in := remediationFixture(t)
	in.Findings[0].PolicyStatus = model.FindingPolicyStatusWarn
	out := buildRemediations(in)
	for _, group := range out.Remediations {
		if group.TargetPackage.Name == "lib-a" {
			t.Fatalf("warn-only vulnerability resurfaced as actionable: %#v", group)
		}
	}
	var warned *CompactFinding
	for idx := range out.Informational {
		if out.Informational[idx].Package.Name == "lib-a" {
			warned = &out.Informational[idx]
			break
		}
	}
	if warned == nil || warned.PolicyStatus != string(model.FindingPolicyStatusWarn) {
		t.Fatalf("warn+fix_available was not retained as informational: %#v", out.Informational)
	}
}

func TestBuildCompactScanTreatsAuditOmissionsAsSuppressed(t *testing.T) {
	in := remediationFixture(t)
	run := ScanRunResult{
		Response: output.ScanResponse{
			Manifests: in.Manifests,
			Packages:  output.PackagesFromRegistry(in.Registry),
		},
		// Omit lib-a as if allow_vulnerability_ids or --fail-on excluded it.
		Findings:  append([]model.Finding(nil), in.Findings[1:]...),
		Graph:     in.Graph,
		Registry:  in.Registry,
		EnrichRan: true,
		AuditRan:  true,
	}

	compact := BuildCompactScan(run)
	for _, group := range compact.Remediations {
		if group.TargetPackage.Name == "lib-a" {
			t.Fatalf("audit-suppressed lib-a became actionable: %#v", group)
		}
	}
	for _, finding := range compact.Informational {
		if finding.Package.Name == "lib-a" {
			if finding.PolicyStatus != string(model.FindingPolicyStatusSuppressed) {
				t.Fatalf("lib-a policy status = %q, want suppressed", finding.PolicyStatus)
			}
			return
		}
	}
	t.Fatalf("audit-suppressed lib-a missing from informational findings: %#v", compact.Informational)
}

// An auditor that records no DependencyRefs leaves the finding's package
// reference as the only way back into the graph. That path used to walk every
// node once per finding; it now joins through the SDK's package-to-nodes
// reverse index, and this pins that the join still lands on the same node --
// the placement facts (transitive, and the path through lib-b) are only
// derivable once the node is found.
func TestBuildRemediationsPlacesFindingsWithoutDependencyRefs(t *testing.T) {
	in := remediationFixture(t)
	for idx := range in.Findings {
		in.Findings[idx].DependencyRefs = nil
	}

	// The informational bucket is where the join is observable: a grouped fix
	// takes its placement from the suggestion's own dependency refs, but an
	// informational finding keeps whatever buildCompactFinding derived from
	// the node it resolved.
	out := buildRemediations(in)
	if len(out.Informational) != 1 {
		t.Fatalf("informational bucket = %#v", out.Informational)
	}
	got := out.Informational[0]
	if got.Direct == nil || !*got.Direct {
		t.Fatalf("lib-a is direct; its node was not found from the package reference alone: %#v", got.Direct)
	}
	wantPath := []string{"app@1.0.0", "lib-a@1.0.0"}
	if len(got.ShortestPath) != len(wantPath) {
		t.Fatalf("shortest path = %#v, want %#v", got.ShortestPath, wantPath)
	}
	for idx := range wantPath {
		if got.ShortestPath[idx] != wantPath[idx] {
			t.Fatalf("shortest path = %#v, want %#v", got.ShortestPath, wantPath)
		}
	}
}

// The index is a view over a graph, never a record of one: a stale index is
// how the reverse direction of a stored fact goes wrong. Nothing may hand
// buildRemediations an index built from a different graph than the one it is
// about to walk.
func TestRemediationInputIndexesTheGraphItWasGiven(t *testing.T) {
	in := remediationFixture(t)
	in.indexNodes()
	for _, f := range in.Findings {
		nodes := in.Nodes.Nodes(f.PackageRef)
		if len(nodes) == 0 {
			continue
		}
		if _, ok := in.Graph.Node(nodes[0].NodeID()); !ok {
			t.Fatalf("index holds node %q that is not in the graph", nodes[0].NodeID())
		}
	}
	if len(in.Nodes) != len(in.Graph.DependencyNodes()) {
		t.Fatalf("index covers %d packages, graph holds %d dependency nodes", len(in.Nodes), len(in.Graph.DependencyNodes()))
	}
}
