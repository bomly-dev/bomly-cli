package mcp

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRemediationActionRequiresManualReviewForUnknownParent(t *testing.T) {
	got := remediationAction(
		sdk.Finding{Kind: sdk.FindingKindVulnerability},
		&sdk.Vulnerability{FixedIn: "2.0.0"},
		CompactFinding{Classification: ClassificationFixAvailable},
		ancestorTarget{unresolvedParent: true},
		"npm",
	)
	if got != ActionManualReview {
		t.Fatalf("remediationAction() = %q, want %q", got, ActionManualReview)
	}
}

// remediationFixture builds a small realistic scan state:
//
//	app@1.0.0 (root)
//	├── lib-a@1.0.0            vulnerable, fixed in 1.2.0   → direct-bump
//	├── lib-b@1.0.0
//	│   └── @scope/deep@2.0.0  vulnerable (KEV), fixed 2.1.0 → transitive-override via lib-b
//	└── legacy@0.1.0           vulnerable, no fix            → no-fix-upstream
func remediationFixture(t *testing.T) remediationInput {
	t.Helper()
	g := sdk.New()
	nodes := []*sdk.Dependency{
		sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "app", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/app@1.0.0"}}),
		sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lib-a", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lib-a@1.0.0"}}),
		sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lib-b", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lib-b@1.0.0"}}),
		sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Org: "scope", Name: "deep", Version: "2.0.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/@scope/deep@2.0.0"}}),
		sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "legacy", Version: "0.1.0", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/legacy@0.1.0"}}),
	}
	for _, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("add node %s: %v", node.ID, err)
		}
	}
	edges := [][2]string{
		{nodes[0].ID, nodes[1].ID},
		{nodes[0].ID, nodes[2].ID},
		{nodes[2].ID, nodes[3].ID},
		{nodes[0].ID, nodes[4].ID},
	}
	for _, edge := range edges {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %v: %v", edge, err)
		}
	}

	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/lib-a@1.0.0", Name: "lib-a", Version: "1.0.0", Ecosystem: sdk.EcosystemNPM},
		Vulnerabilities: []sdk.Vulnerability{{
			ID: "GHSA-liba", Aliases: []string{"CVE-2026-1111"}, Source: "osv",
			ParsedSeverity: sdk.SeverityHigh, FixState: sdk.FixStateFixed, FixedIn: "1.2.0",
		}},
	})
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/@scope/deep@2.0.0", Org: "scope", Name: "deep", Version: "2.0.0", Ecosystem: sdk.EcosystemNPM},
		Vulnerabilities: []sdk.Vulnerability{{
			ID: "GHSA-deep", Source: "osv",
			ParsedSeverity: sdk.SeverityMedium, FixState: sdk.FixStateFixed, FixedIn: "2.1.0",
			KEVExploited: true,
			EPSS:         []sdk.EPSSScore{{EPSS: 0.92}},
		}},
	})
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: "pkg:npm/legacy@0.1.0", Name: "legacy", Version: "0.1.0", Ecosystem: sdk.EcosystemNPM},
		Vulnerabilities: []sdk.Vulnerability{{
			ID: "GHSA-legacy", Source: "osv",
			ParsedSeverity: sdk.SeverityCritical, FixState: sdk.FixStateNotFixed,
		}},
	})

	manifest := output.ScanManifest{
		Path:           "package.json",
		PackageManager: sdk.PackageManagerNPM,
		Dependencies: []output.ScanDependency{
			{ID: nodes[0].ID, Name: "app", Version: "1.0.0"},
			{ID: nodes[1].ID, Name: "lib-a", Version: "1.0.0"},
			{ID: nodes[2].ID, Name: "lib-b", Version: "1.0.0"},
			{ID: nodes[3].ID, Name: "@scope/deep", Version: "2.0.0"},
			{ID: nodes[4].ID, Name: "legacy", Version: "0.1.0"},
		},
	}

	findings := []sdk.Finding{
		{
			ID: "GHSA-liba", VulnerabilityID: "GHSA-liba", Kind: sdk.FindingKindVulnerability,
			Severity: sdk.SeverityHigh, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/lib-a@1.0.0", DependencyRefs: []string{nodes[1].ID},
		},
		{
			ID: "GHSA-deep", VulnerabilityID: "GHSA-deep", Kind: sdk.FindingKindVulnerability,
			Severity: sdk.SeverityMedium, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/@scope/deep@2.0.0", DependencyRefs: []string{nodes[3].ID},
		},
		{
			ID: "GHSA-legacy", VulnerabilityID: "GHSA-legacy", Kind: sdk.FindingKindVulnerability,
			Severity: sdk.SeverityCritical, Source: "osv", Auditor: "vulnerability",
			PackageRef: "pkg:npm/legacy@0.1.0", DependencyRefs: []string{nodes[4].ID},
		},
		{
			ID: "license:unknown-license:lib-a@1.0.0", Kind: sdk.FindingKindLicense,
			Severity: "n/a", Source: "license", Auditor: "license",
			RuleID:       "unknown-license",
			PolicyStatus: sdk.FindingPolicyStatusWarn,
			PackageRef:   "pkg:npm/lib-a@1.0.0", DependencyRefs: []string{nodes[1].ID},
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
	if len(out.Informational) != 1 || out.Informational[0].Kind != string(sdk.FindingKindLicense) {
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
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, sdk.Vulnerability{
			ID: "GHSA-liba2", Source: "osv",
			ParsedSeverity: sdk.SeverityLow, FixState: sdk.FixStateFixed, FixedIn: "1.3.0",
		})
	}
	in.Findings = append(in.Findings, sdk.Finding{
		ID: "GHSA-liba2", VulnerabilityID: "GHSA-liba2", Kind: sdk.FindingKindVulnerability,
		Severity: sdk.SeverityLow, Source: "osv", Auditor: "vulnerability",
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
	for i := 0; i < maxRemediationGroups+10; i++ {
		purl := fmt.Sprintf("pkg:npm/synth-%03d@1.0.0", i)
		in.Registry.Add(&sdk.Package{
			Coordinates: sdk.Coordinates{PURL: purl, Name: fmt.Sprintf("synth-%03d", i), Version: "1.0.0", Ecosystem: sdk.EcosystemNPM},
			Vulnerabilities: []sdk.Vulnerability{{
				ID: fmt.Sprintf("GHSA-synth-%03d", i), Source: "osv",
				ParsedSeverity: sdk.SeverityLow, FixState: sdk.FixStateNotFixed,
			}},
		})
		in.Findings = append(in.Findings, sdk.Finding{
			ID:              fmt.Sprintf("GHSA-synth-%03d", i),
			VulnerabilityID: fmt.Sprintf("GHSA-synth-%03d", i),
			Kind:            sdk.FindingKindVulnerability,
			Severity:        sdk.SeverityLow, Source: "osv", Auditor: "vulnerability",
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

func TestShortestPathBoundsLongChains(t *testing.T) {
	g := sdk.New()
	var previous string
	for i := 0; i < 10; i++ {
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: fmt.Sprintf("chain-%d", i), Version: "1.0.0", Ecosystem: sdk.EcosystemNPM,
			PURL: fmt.Sprintf("pkg:npm/chain-%d@1.0.0", i),
		}})
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
		if previous != "" {
			if err := g.AddEdge(previous, node.ID); err != nil {
				t.Fatal(err)
			}
		}
		previous = node.ID
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
	for i := 0; i < 12; i++ {
		purl := fmt.Sprintf("pkg:npm/extra-%02d@1.0.0", i)
		in.Registry.Add(&sdk.Package{
			Coordinates: sdk.Coordinates{PURL: purl, Name: fmt.Sprintf("extra-%02d", i), Version: "1.0.0", Ecosystem: sdk.EcosystemNPM},
			Vulnerabilities: []sdk.Vulnerability{{
				ID: fmt.Sprintf("GHSA-extra-%02d", i), Source: "osv",
				ParsedSeverity: sdk.SeverityHigh, FixState: sdk.FixStateFixed, FixedIn: "1.1.0",
				Details:    "a very long advisory description that must never appear in the compact response because it belongs to the drill-down path only",
				References: []sdk.Reference{{URL: "https://example.com/advisory"}},
			}},
		})
		in.Findings = append(in.Findings, sdk.Finding{
			ID:              fmt.Sprintf("GHSA-extra-%02d", i),
			VulnerabilityID: fmt.Sprintf("GHSA-extra-%02d", i),
			Kind:            sdk.FindingKindVulnerability,
			Severity:        sdk.SeverityHigh, Source: "osv", Auditor: "vulnerability",
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

func TestClassifyFindingMatrix(t *testing.T) {
	cases := []struct {
		name string
		f    sdk.Finding
		vuln *sdk.Vulnerability
		want string
	}{
		{"license", sdk.Finding{Kind: sdk.FindingKindLicense}, nil, ClassificationPolicyOnly},
		{"package", sdk.Finding{Kind: sdk.FindingKindPackage}, nil, ClassificationPolicyOnly},
		{"no advisory data", sdk.Finding{Kind: sdk.FindingKindVulnerability}, nil, ClassificationUnknown},
		{"fixed state", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixState: sdk.FixStateFixed}, ClassificationFixAvailable},
		{"fixed-in only", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixedIn: "1.2.3"}, ClassificationFixAvailable},
		{"fixed versions", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixedVersions: []string{"2.0.0"}}, ClassificationFixAvailable},
		{"fix available list", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixAvailable: []sdk.FixAvailable{{Version: "2.0.0"}}}, ClassificationFixAvailable},
		{"wont fix", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixState: sdk.FixStateWontFix}, ClassificationWontFix},
		{"not fixed", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixState: sdk.FixStateNotFixed}, ClassificationNoFixUpstream},
		{"unknown state", sdk.Finding{Kind: sdk.FindingKindVulnerability}, &sdk.Vulnerability{FixState: sdk.FixStateUnknown}, ClassificationUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFinding(tc.f, tc.vuln); got != tc.want {
				t.Errorf("classifyFinding() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWarnWithFixAvailableStaysActionable(t *testing.T) {
	in := remediationFixture(t)
	// Downgrade the lib-a vulnerability finding to warning status: a fix
	// is available, so it must still surface as a remediation (cheap win),
	// carrying its policy status.
	in.Findings[0].PolicyStatus = sdk.FindingPolicyStatusWarn
	out := buildRemediations(in)
	direct := groupByAction(t, out.Remediations, ActionDirectBump)
	if len(direct.Fixes) != 1 || direct.Fixes[0].PolicyStatus != string(sdk.FindingPolicyStatusWarn) {
		t.Fatalf("warn+fix_available should stay actionable: %#v", direct)
	}
}
