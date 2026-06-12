package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// fixtureDiffPayload returns a representative DiffResponse covering every
// aggregation surface: multiple ecosystems, multiple scopes, fuzzy + exact
// reconciled changes, vulnerability findings, and policy-kind findings
// (so we can exercise the kind split). The goldens for every aggregation
// in this file are computed from this single payload.
func fixtureDiffPayload() output.DiffResponse {
	return output.DiffResponse{
		Project:    output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"},
		Comparison: output.DiffComparison{Base: "main", Head: "feature"},
		Summary: output.DiffSummary{
			AddedManifestCount: 1, ChangedManifestCount: 1, RemovedManifestCount: 0, UnchangedManifestCount: 0,
			AddedPackageCount: 2, ChangedPackageCount: 2, RemovedPackageCount: 1,
		},
		Results: output.DiffResults{Manifests: []output.DiffManifestResult{
			{
				Status: "added", Path: "package.json", Ecosystem: "npm", PackageManager: "npm",
				Added: []output.DiffPackageChange{
					{Package: output.PackageRef{ID: "zod@3.23.0", Name: "zod", Version: "3.23.0", Scope: "runtime", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
				},
			},
			{
				Status: "changed", Path: "go.mod", Ecosystem: "go", PackageManager: "gomod",
				Added: []output.DiffPackageChange{
					{Package: output.PackageRef{ID: "github.com/new/pkg@1.0.0", Name: "github.com/new/pkg", Version: "1.0.0", Scope: "development",
						Licenses: []output.LicenseRef{{SPDXExpression: "Apache-2.0"}}}},
				},
				Changed: []output.DiffChangedPackage{
					// Exact match (same name, version change) — no fuzzy metadata.
					{Before: output.PackageRef{ID: "react@18.2.0", Name: "react", Version: "18.2.0", Scope: "runtime", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}},
						After: output.PackageRef{ID: "react@19.0.0", Name: "react", Version: "19.0.0", Scope: "runtime", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
					// Fuzzy reconciled — After carries the metadata marker.
					{Before: output.PackageRef{ID: "old-pkg@1.0.0", Name: "old-pkg", Version: "1.0.0", Licenses: []output.LicenseRef{{SPDXExpression: "BSD-2-Clause"}}},
						After: output.PackageRef{ID: "new-pkg@1.1.0", Name: "new-pkg", Version: "1.1.0", Scope: "runtime",
							Metadata: map[string]any{"bomly.diff.fuzzy_reconciled": true},
							Licenses: []output.LicenseRef{{SPDXExpression: "BSD-2-Clause"}, {SPDXExpression: "MIT"}}}},
				},
				Removed: []output.DiffPackageChange{
					{Package: output.PackageRef{ID: "dropped@0.1.0", Name: "dropped", Version: "0.1.0", Licenses: []output.LicenseRef{{SPDXExpression: "Apache-2.0"}}}},
				},
			},
		}},
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{
				{ID: "CVE-2024-0001", Kind: "vulnerability", Severity: "high", Source: "osv", Package: output.PackageRef{Name: "react", Version: "19.0.0"}},
				{ID: "license:unknown-license:zod@3.23.0", Kind: string(sdk.FindingKindLicense), Severity: "unknown", Auditor: "license", Source: "license", Package: output.PackageRef{Name: "zod", Version: "3.23.0"}},
			},
			Persisted: []output.AuditFinding{
				{ID: "CVE-2023-9999", Kind: "vulnerability", Severity: "medium", Source: "osv", Package: output.PackageRef{Name: "lodash", Version: "4.17.20"}},
			},
			Resolved: []output.AuditFinding{
				{ID: "CVE-2022-1111", Kind: "vulnerability", Severity: "low", Source: "osv", Package: output.PackageRef{Name: "dropped", Version: "0.1.0"}},
			},
			// AuditSummary.Total now reflects Introduced + Persisted only
			// (scan_output.go no longer appends Resolved). For this fixture
			// that's 2 introduced + 1 persisted = 3.
			AuditSummary: &output.AuditSummary{High: 1, Medium: 2, Low: 0, Total: 3},
		},
	}
}

func newFixtureDiffModel() *DiffModel {
	return NewDiff(fixtureDiffPayload(), sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
}

// ---- diffAggregateCounts (footer) -----------------------------------------

func TestDiffAggregateCounts_FromFixture(t *testing.T) {
	m := newFixtureDiffModel()
	c := m.diffAggregateCounts()

	// Manifest deltas = Added(1) + Changed(1) + Removed(0).
	if c.ManifestDeltas != 2 {
		t.Errorf("ManifestDeltas = %d, want 2", c.ManifestDeltas)
	}
	// Package deltas = Added(2) + Changed(2) + Removed(1).
	if c.PackageDeltas != 5 {
		t.Errorf("PackageDeltas = %d, want 5", c.PackageDeltas)
	}
	// Vuln deltas: 1 introduced vuln + 1 persisted vuln + 1 resolved vuln = 3.
	// Persisted MUST be included — that's the regression we want to lock in.
	if c.VulnDeltas != 3 {
		t.Errorf("VulnDeltas = %d, want 3 (Introduced+Persisted+Resolved vulnerability-kind)", c.VulnDeltas)
	}
	// Finding deltas: 1 policy-kind in Introduced.
	if c.FindingDeltas != 1 {
		t.Errorf("FindingDeltas = %d, want 1", c.FindingDeltas)
	}
	// Unique licenses introduced/retired:
	//   added(zod):     MIT
	//   added(new/pkg): Apache-2.0
	//   changed(new-pkg adds MIT — already there? no, it's introduced via fuzzy):
	//     before licenses = {BSD-2-Clause}, after = {BSD-2-Clause, MIT}
	//     → MIT introduced
	//   removed(dropped): Apache-2.0 retired
	// Distinct SPDX ids touched: {MIT, Apache-2.0, BSD-2-Clause? no — BSD-2-Clause
	// is in both before and after of the fuzzy change so it's neither introduced
	// nor retired} ∪ {Apache-2.0 retired} = {MIT, Apache-2.0}.
	if got, want := c.LicenseUniqueDeltas, 2; got != want {
		t.Errorf("LicenseUniqueDeltas = %d, want %d (unique SPDX IDs introduced or retired)", got, want)
	}
}

func TestDiffAggregateCounts_EmptyPayload(t *testing.T) {
	m := NewDiff(output.DiffResponse{}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	c := m.diffAggregateCounts()
	if c.ManifestDeltas != 0 || c.PackageDeltas != 0 || c.VulnDeltas != 0 || c.FindingDeltas != 0 || c.LicenseUniqueDeltas != 0 {
		t.Errorf("empty payload should yield zero counts, got %+v", c)
	}
}

func TestDiffAggregateCounts_LicenseDedup(t *testing.T) {
	// Five packages all introduce MIT — unique count should be 1, not 5.
	payload := output.DiffResponse{Results: output.DiffResults{Manifests: []output.DiffManifestResult{{
		Status: "added", Path: "pkg.json", Ecosystem: "npm",
		Added: []output.DiffPackageChange{
			{Package: output.PackageRef{Name: "a", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
			{Package: output.PackageRef{Name: "b", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
			{Package: output.PackageRef{Name: "c", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
			{Package: output.PackageRef{Name: "d", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
			{Package: output.PackageRef{Name: "e", Licenses: []output.LicenseRef{{SPDXExpression: "MIT"}}}},
		},
	}}}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	if got := m.diffAggregateCounts().LicenseUniqueDeltas; got != 1 {
		t.Errorf("LicenseUniqueDeltas = %d, want 1", got)
	}
}

func TestDiffFooterSummary_RendersAllFields(t *testing.T) {
	m := newFixtureDiffModel()
	got := m.diffFooterSummary()
	wants := []string{"Manifests: 2", "Packages: 5", "Vulns: 3", "Licenses: 2", "Findings: 1"}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("diffFooterSummary missing %q in %q", w, got)
		}
	}
}

// ---- computeOverviewStats -------------------------------------------------

func TestComputeOverviewStats_EcosystemsBucketed(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	// Manifest 1 ("added") has 1 package change in npm.
	// Manifest 2 ("changed") has 1 added + 2 changed + 1 removed = 4 in go.
	if got := stats.ecosystems["npm"]; got != 1 {
		t.Errorf("ecosystems[npm] = %d, want 1", got)
	}
	if got := stats.ecosystems["go"]; got != 4 {
		t.Errorf("ecosystems[go] = %d, want 4", got)
	}
	// changedTotal = sum of ecosystems.
	if stats.changedTotal != 5 {
		t.Errorf("changedTotal = %d, want 5", stats.changedTotal)
	}
}

func TestComputeOverviewStats_ScopesAreStatusComposite(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	// New shape: composite keys "<status> <scope>". A user grouping the
	// Scope pane wants "added runtime" and "removed runtime" to be visibly
	// distinct buckets — the previous flat shape merged them.
	//   added(zod, runtime)               → "added runtime"
	//   added(new/pkg, development)       → "added development"
	//   changed(react, after=runtime)     → "changed runtime"
	//   changed(new-pkg, after=runtime)   → "changed runtime"
	//   removed(dropped, no scope)        → "removed unset"
	wants := map[string]int{
		"added runtime":     1,
		"added development": 1,
		"changed runtime":   2,
		"removed unset":     1,
	}
	for key, want := range wants {
		if got := stats.scopes[key]; got != want {
			t.Errorf("scopes[%q] = %d, want %d", key, got, want)
		}
	}
	if total := sumCounts(stats.scopes); total != 5 {
		t.Errorf("sumCounts(scopes) = %d, want 5 (= PackageDeltas)", total)
	}
}

func TestComputeOverviewStats_RelationshipsScopedToChanges(t *testing.T) {
	// Build a head graph where react is root, lodash is direct, otherwise transitive.
	g := sdk.New()
	react := sdk.NewDependencyRef("react", "19.0.0")
	lodash := sdk.NewDependencyRef("lodash", "4.17.20")
	if err := g.AddNode(react); err != nil {
		t.Fatalf("add react: %v", err)
	}
	if err := g.AddNode(lodash); err != nil {
		t.Fatalf("add lodash: %v", err)
	}
	if err := g.AddEdge(react.ID, lodash.ID); err != nil {
		t.Fatalf("add dep: %v", err)
	}

	payload := output.DiffResponse{Results: output.DiffResults{Manifests: []output.DiffManifestResult{{
		Status: "changed", Path: "package.json", Ecosystem: "npm",
		Changed: []output.DiffChangedPackage{
			{Before: output.PackageRef{Name: "react", Version: "18.2.0"}, After: output.PackageRef{ID: react.ID, Name: "react", Version: "19.0.0"}},
		},
		Added: []output.DiffPackageChange{
			{Package: output.PackageRef{ID: lodash.ID, Name: "lodash", Version: "4.17.20"}},
		},
		Removed: []output.DiffPackageChange{
			{Package: output.PackageRef{Name: "old-pkg", Version: "1.0.0"}}, // not in head graph
		},
	}}}}

	consolidated := sdk.ConsolidatedGraph{Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json"})}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, consolidated)
	stats := m.computeOverviewStats()

	// New shape: composite keys "<status> <relationship>".
	//   changed(react) — present in head, classified root → "changed root"
	//   added(lodash)  — present in head as react's dep    → "added direct"
	//   removed(old-pkg) — not in any graph (test has no base graph)
	//                                                       → "removed unknown"
	wants := map[string]int{
		"changed root":    1,
		"added direct":    1,
		"removed unknown": 1,
	}
	for key, want := range wants {
		if got := stats.relationships[key]; got != want {
			t.Errorf("relationships[%q] = %d, want %d", key, got, want)
		}
	}
	// Sum must equal package-change events, NOT total head-graph packages —
	// that's the regression we want to lock in.
	if total := sumCounts(stats.relationships); total != 3 {
		t.Errorf("sumCounts(relationships) = %d, want 3 (number of CHANGE events)", total)
	}
}

func TestComputeOverviewStats_RemovedPkgUsesBaseGraphForRelationship(t *testing.T) {
	// Build a base graph where "old-pkg" is direct (under a root); build a
	// head graph that does NOT contain it. The Overview must classify it
	// as "removed direct", not "removed unknown".
	baseG := sdk.New()
	root := sdk.NewDependencyRef("root", "1")
	old := sdk.NewDependencyRef("old-pkg", "1.0.0")
	for _, p := range []*sdk.Dependency{root, old} {
		if err := baseG.AddNode(p); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := baseG.AddEdge(root.ID, old.ID); err != nil {
		t.Fatalf("dep: %v", err)
	}

	payload := output.DiffResponse{Results: output.DiffResults{Manifests: []output.DiffManifestResult{{
		Status: "changed", Path: "go.mod", Ecosystem: "go",
		Removed: []output.DiffPackageChange{
			{Package: output.PackageRef{ID: old.ID, Name: "old-pkg", Version: "1.0.0"}},
		},
	}}}}
	base := sdk.ConsolidatedGraph{Graphs: sdk.SingleGraphContainer(baseG, sdk.ManifestMetadata{Path: "go.mod"})}
	m := NewDiff(payload, base, sdk.ConsolidatedGraph{})
	stats := m.computeOverviewStats()
	if got := stats.relationships["removed direct"]; got != 1 {
		t.Errorf("relationships[removed direct] = %d, want 1 (looked up in BASE graph)", got)
	}
	if got := stats.relationships["removed unknown"]; got != 0 {
		t.Errorf("relationships[removed unknown] = %d, want 0 — base graph should rescue removed pkgs", got)
	}
}

func TestComputeOverviewStats_FuzzyAndExactReconciliation(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	if stats.matchedExact != 1 {
		t.Errorf("matchedExact = %d, want 1 (react)", stats.matchedExact)
	}
	if stats.matchedFuzzy != 1 {
		t.Errorf("matchedFuzzy = %d, want 1 (new-pkg)", stats.matchedFuzzy)
	}
	// unmatched* count Added/Removed packages as-is. Fuzzy reconciliation
	// already moved its matches out of Added/Removed into Changed, so an
	// added entry here means it really had no peer.
	if stats.unmatchedAdded != 2 {
		t.Errorf("unmatchedAdded = %d, want 2", stats.unmatchedAdded)
	}
	if stats.unmatchedRemoved != 1 {
		t.Errorf("unmatchedRemoved = %d, want 1", stats.unmatchedRemoved)
	}
}

func TestComputeOverviewStats_VulnByStatusIsVulnKindOnly(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	// vulnByStatus is keyed by severity row -> { status -> count }.
	// 3 vuln-kind findings:
	//   high introduced   (CVE-2024-0001)
	//   medium persisted  (CVE-2023-9999)
	//   low resolved      (CVE-2022-1111)
	// The POLICY-1 (medium, license-kind) finding MUST NOT appear in
	// this table — it lives in licenseByStatus instead.
	type cell struct{ row, status string }
	wants := map[cell]int{
		{"high", "introduced"}:  1,
		{"medium", "persisted"}: 1,
		{"low", "resolved"}:     1,
	}
	for k, want := range wants {
		if got := stats.vulnByStatus[k.row][k.status]; got != want {
			t.Errorf("vulnByStatus[%q][%q] = %d, want %d", k.row, k.status, got, want)
		}
	}
	if got := stats.vulnByStatus["medium"]["introduced"]; got != 0 {
		t.Errorf("vulnByStatus[medium][introduced] = %d, want 0 — POLICY-1 must be excluded", got)
	}
	total := 0
	for _, row := range stats.vulnByStatus {
		for _, n := range row {
			total += n
		}
	}
	if total != 3 {
		t.Errorf("vulnByStatus total = %d, want 3 (vuln-kind, all 3 buckets)", total)
	}
}

func TestComputeOverviewStats_FindingsByKindFromFixture(t *testing.T) {
	// findingsByKind reads AuditFinding.Kind directly. The fixture has
	// 3 vulnerability-kind findings and 1 license-kind finding.
	stats := newFixtureDiffModel().computeOverviewStats()
	if got := stats.findingsByKind["vulnerability"]; got != 3 {
		t.Errorf("findingsByKind[vulnerability] = %d, want 3", got)
	}
	if got := stats.findingsByKind["license"]; got != 1 {
		t.Errorf("findingsByKind[license] = %d, want 1", got)
	}
	if got := stats.findingsByKind["package"]; got != 0 {
		t.Errorf("findingsByKind[package] = %d, want 0", got)
	}
	if total := sumCounts(stats.findingsByKind); total != 4 {
		t.Errorf("sumCounts(findingsByKind) = %d, want 4", total)
	}
}

func TestComputeOverviewStats_LicenseAndPackageByStatus(t *testing.T) {
	// Build a payload exercising every license and package rule so the
	// tables include rows with meaningful counts and the "(other)" row
	// when the rule keyword isn't one we know about.
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "license:unknown-license:pkg@1", Kind: "license", Auditor: "license"},
			{ID: "license:invalid-license:pkg@2", Kind: "license", Auditor: "license"},
			{ID: "license:denied-license:pkg@3", Kind: "license", Auditor: "license"},
			{ID: "package:denied-package:pkg@4", Kind: "package", Auditor: "package"},
			{ID: "package:denied-group:pkg@5", Kind: "package", Auditor: "package"},
			{ID: "package:suspicious-package:pkg@6", Kind: "package", Auditor: "package"},
		},
		Persisted: []output.AuditFinding{
			{ID: "license:unknown-license:pkg@7", Kind: "license", Auditor: "license"},
			// External plugin emitting a kind we don't know — must land
			// in the "other" row.
			{ID: "ext:weird-rule:pkg@8", Kind: "package", Auditor: "external"},
		},
		Resolved: []output.AuditFinding{
			{ID: "license:denied-license:pkg@9", Kind: "license", Auditor: "license"},
		},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	stats := m.computeOverviewStats()

	// License table.
	licenseWants := map[string]map[string]int{
		"unknown": {"introduced": 1, "persisted": 1, "resolved": 0},
		"invalid": {"introduced": 1, "persisted": 0, "resolved": 0},
		"denied":  {"introduced": 1, "persisted": 0, "resolved": 1},
	}
	for row, want := range licenseWants {
		for status, n := range want {
			if got := stats.licenseByStatus[row][status]; got != n {
				t.Errorf("licenseByStatus[%q][%q] = %d, want %d", row, status, got, n)
			}
		}
	}

	// Package table.
	packageWants := map[string]map[string]int{
		"denied":       {"introduced": 1, "persisted": 0, "resolved": 0},
		"denied-group": {"introduced": 1, "persisted": 0, "resolved": 0},
		"suspicious":   {"introduced": 1, "persisted": 0, "resolved": 0},
		// External "weird-rule" lands in the "other" row.
		"other": {"introduced": 0, "persisted": 1, "resolved": 0},
	}
	for row, want := range packageWants {
		for status, n := range want {
			if got := stats.packageByStatus[row][status]; got != n {
				t.Errorf("packageByStatus[%q][%q] = %d, want %d", row, status, got, n)
			}
		}
	}
}

func TestFindingKindOf_ClassifiesBuiltinAuditors(t *testing.T) {
	cases := []struct {
		f    output.AuditFinding
		want string
	}{
		{output.AuditFinding{Kind: "vulnerability"}, "vulnerability"},
		{output.AuditFinding{Kind: "license"}, "license"},
		{output.AuditFinding{Kind: "package"}, "package"},
		{output.AuditFinding{Kind: "vuln"}, "vulnerability"},     // alias
		{output.AuditFinding{Kind: "advisory"}, "vulnerability"}, // alias
		{output.AuditFinding{Kind: "cve"}, "vulnerability"},      // alias
		// Empty Kind → fall back to id/source heuristic.
		{output.AuditFinding{ID: "CVE-2024-0001"}, "vulnerability"},
		{output.AuditFinding{Source: "osv"}, "vulnerability"},
		{output.AuditFinding{Auditor: "license"}, "license"},
		{output.AuditFinding{Auditor: "package"}, "package"},
		// Truly unknown.
		{output.AuditFinding{}, "other"},
	}
	for _, tc := range cases {
		if got := findingKindOf(tc.f); got != tc.want {
			t.Errorf("findingKindOf(%#v) = %q, want %q", tc.f, got, tc.want)
		}
	}
}

func TestFindingRule_StripsAuditorPrefixAndSuffix(t *testing.T) {
	cases := []struct {
		id, fallback, want string
	}{
		{"BOMLY-LIC-UNKNOWN", "fb", "unknown"},
		{"license:unknown-license:pkg@1", "fb", "unknown"},
		{"license:invalid-license:pkg@1", "fb", "invalid"},
		{"license:denied-license:pkg@1", "fb", "denied"},
		{"package:denied-package:pkg@1", "fb", "denied"},
		{"package:denied-group:pkg@1", "fb", "denied-group"},
		{"package:suspicious-package:pkg@1", "fb", "suspicious"},
		// ID with no rule chunk falls back.
		{"singleton", "fb", "fb"},
		{"", "fb", "fb"},
	}
	for _, tc := range cases {
		got := findingRule(output.AuditFinding{ID: tc.id}, tc.fallback)
		if got != tc.want {
			t.Errorf("findingRule(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestComputeOverviewStats_AuditRanAndTotal(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	if !stats.auditRan {
		t.Errorf("auditRan = false, want true")
	}
	// auditSummaryTotal passes through AuditSummary.Total verbatim. With
	// the current scan_output.go that's Introduced+Persisted (not Resolved).
	// The exit-code gate is NOT this number — see auditVerdict.FailingIntroduced.
	if stats.auditSummaryTotal != 3 {
		t.Errorf("auditSummaryTotal = %d, want 3 (Introduced+Persisted from fixture)", stats.auditSummaryTotal)
	}

	noAudit := NewDiff(output.DiffResponse{}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	if got := noAudit.computeOverviewStats(); got.auditRan {
		t.Errorf("auditRan = true for payload without Audit, want false")
	}
}

// ---- auditVerdict (mirrors diff_cmd.go:161-165) ---------------------------

func TestAuditVerdict_NotEvaluatedWhenAuditMissing(t *testing.T) {
	m := NewDiff(output.DiffResponse{}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	v := m.auditVerdict()
	if v.Ran {
		t.Errorf("v.Ran = true, want false")
	}
	if got := v.Verdict(); got != "NOT EVALUATED" {
		t.Errorf("Verdict() = %q, want NOT EVALUATED", got)
	}
}

func TestAuditVerdict_PassWhenNoIntroduced(t *testing.T) {
	m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{AuditSummary: &output.AuditSummary{Total: 0}}},
		sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	v := m.auditVerdict()
	if !v.Ran {
		t.Errorf("v.Ran = false, want true")
	}
	if got := v.Verdict(); got != "PASS" {
		t.Errorf("Verdict() = %q, want PASS", got)
	}
}

// Regression for the diff exit-code gate (internal/cli/diff_cmd.go:161-165):
// the gate operates on *Introduced* findings ONLY via output.FailingFindingCount.
// A diff that resolves findings — even high-severity ones — must NOT FAIL.
func TestAuditVerdict_ResolvedOnlyIsPass(t *testing.T) {
	m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{
		Resolved:     []output.AuditFinding{{ID: "CVE-2022-X", Kind: "vulnerability", Severity: "high", Source: "osv"}},
		AuditSummary: &output.AuditSummary{},
	}}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	v := m.auditVerdict()
	if got := v.Verdict(); got != "PASS" {
		t.Errorf("Verdict() = %q, want PASS (only Resolved findings; no introduced gate)", got)
	}
	if v.FailingIntroduced != 0 {
		t.Errorf("FailingIntroduced = %d, want 0", v.FailingIntroduced)
	}
	if v.ResolvedTotal != 1 {
		t.Errorf("ResolvedTotal = %d, want 1", v.ResolvedTotal)
	}
}

// Persisted findings on their own also do NOT fail the diff: the gate
// runs on Introduced only.
func TestAuditVerdict_PersistedOnlyIsPass(t *testing.T) {
	m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{
		Persisted:    []output.AuditFinding{{ID: "CVE-2023-X", Kind: "vulnerability", Severity: "critical", Source: "osv"}},
		AuditSummary: &output.AuditSummary{Critical: 1, Total: 1},
	}}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	if got := m.auditVerdict().Verdict(); got != "PASS" {
		t.Errorf("Verdict() = %q, want PASS (Persisted is not gated by FailingFindingCount)", got)
	}
}

// Disposition gate: an introduced finding with Disposition="warn" must NOT
// trip the FAIL exit; only "" (unset, historically = fail) or "fail" do.
// Mirrors output.FailingFindingCount in internal/output/types.go.
func TestAuditVerdict_DispositionGate(t *testing.T) {
	cases := []struct {
		name        string
		disposition string
		wantFail    bool
	}{
		{"empty disposition (legacy default = fail)", "", true},
		{"explicit fail", string(sdk.FindingDispositionFail), true},
		{"warn does not gate exit code", string(sdk.FindingDispositionWarn), false},
		{"unknown disposition treated as non-failing", "informational", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{
				Introduced: []output.AuditFinding{{
					ID: "X-1", Kind: "vulnerability", Severity: "high", Source: "osv",
					Disposition: tc.disposition,
				}},
				AuditSummary: &output.AuditSummary{High: 1, Total: 1},
			}}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
			v := m.auditVerdict()
			gotFail := v.Verdict() == "FAIL"
			if gotFail != tc.wantFail {
				t.Errorf("Disposition=%q → Verdict=%q (FailingIntroduced=%d), want fail=%v",
					tc.disposition, v.Verdict(), v.FailingIntroduced, tc.wantFail)
			}
		})
	}
}

// When introduced findings exist but ALL are warn-only, the verdict is
// PASS, but the renderer surfaces a "warn-only" badge so the user knows
// findings were detected even though the exit code is clean.
func TestAuditVerdict_WarnOnlyIntroducedYieldsPassWithCount(t *testing.T) {
	m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "W-1", Disposition: string(sdk.FindingDispositionWarn)},
			{ID: "W-2", Disposition: string(sdk.FindingDispositionWarn)},
		},
		AuditSummary: &output.AuditSummary{Total: 2},
	}}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	v := m.auditVerdict()
	if v.Verdict() != "PASS" {
		t.Errorf("Verdict() = %q, want PASS", v.Verdict())
	}
	if v.IntroducedTotal != 2 {
		t.Errorf("IntroducedTotal = %d, want 2", v.IntroducedTotal)
	}
	if v.FailingIntroduced != 0 {
		t.Errorf("FailingIntroduced = %d, want 0 (warn does not gate)", v.FailingIntroduced)
	}
	if v.WarnIntroduced != 2 {
		t.Errorf("WarnIntroduced = %d, want 2", v.WarnIntroduced)
	}
}

func TestAuditVerdict_BucketAndKindBreakdown(t *testing.T) {
	v := newFixtureDiffModel().auditVerdict()
	if v.IntroducedTotal != 2 || v.PersistedTotal != 1 || v.ResolvedTotal != 1 {
		t.Errorf("totals = %d/%d/%d, want 2/1/1", v.IntroducedTotal, v.PersistedTotal, v.ResolvedTotal)
	}
	if v.IntroducedVuln != 1 || v.PersistedVuln != 1 || v.ResolvedVuln != 1 {
		t.Errorf("vuln = %d/%d/%d, want 1/1/1", v.IntroducedVuln, v.PersistedVuln, v.ResolvedVuln)
	}
	if v.IntroducedNonVuln != 1 || v.PersistedNonVuln != 0 || v.ResolvedNonVuln != 0 {
		t.Errorf("nonVuln = %d/%d/%d, want 1/0/0", v.IntroducedNonVuln, v.PersistedNonVuln, v.ResolvedNonVuln)
	}
	if !v.HasNonVulnFindings {
		t.Errorf("HasNonVulnFindings = false, want true (fixture has POLICY-1)")
	}
}

// ---- collectLicenseDeltas / isFuzzyReconciled -----------------------------

func TestCollectLicenseDeltas_IntroducedAndRetiredEvents(t *testing.T) {
	m := newFixtureDiffModel()
	deltas := m.collectLicenseDeltas()

	intro, retired := 0, 0
	uniqueIntro := map[string]struct{}{}
	uniqueRetired := map[string]struct{}{}
	for _, d := range deltas {
		switch d.status {
		case "introduced":
			intro++
			uniqueIntro[d.license] = struct{}{}
		case "retired":
			retired++
			uniqueRetired[d.license] = struct{}{}
		default:
			t.Errorf("unexpected delta status %q", d.status)
		}
	}
	// Events: added(zod MIT) + added(new/pkg Apache-2.0) +
	// changed(new-pkg) introduces MIT (BSD-2-Clause in both before+after) +
	// removed(dropped) retires Apache-2.0.
	if intro != 3 {
		t.Errorf("introduced events = %d, want 3", intro)
	}
	if retired != 1 {
		t.Errorf("retired events = %d, want 1", retired)
	}
	// Unique IDs introduced: {MIT, Apache-2.0}. Retired: {Apache-2.0}.
	if _, ok := uniqueIntro["MIT"]; !ok {
		t.Errorf("expected MIT to be introduced")
	}
	if _, ok := uniqueIntro["Apache-2.0"]; !ok {
		t.Errorf("expected Apache-2.0 to be introduced")
	}
	if _, ok := uniqueRetired["Apache-2.0"]; !ok {
		t.Errorf("expected Apache-2.0 to be retired")
	}
	// BSD-2-Clause appears on BOTH sides of the fuzzy-changed package — it
	// must NOT generate any introduced or retired event.
	if _, ok := uniqueIntro["BSD-2-Clause"]; ok {
		t.Errorf("BSD-2-Clause unchanged across fuzzy match, must not be 'introduced'")
	}
	if _, ok := uniqueRetired["BSD-2-Clause"]; ok {
		t.Errorf("BSD-2-Clause unchanged across fuzzy match, must not be 'retired'")
	}
}

func TestIsFuzzyReconciled(t *testing.T) {
	if isFuzzyReconciled(output.PackageRef{}) {
		t.Errorf("empty ref should not be fuzzy-reconciled")
	}
	if isFuzzyReconciled(output.PackageRef{Metadata: map[string]any{"bomly.diff.fuzzy_reconciled": false}}) {
		t.Errorf("metadata=false should not be fuzzy-reconciled")
	}
	if !isFuzzyReconciled(output.PackageRef{Metadata: map[string]any{"bomly.diff.fuzzy_reconciled": true}}) {
		t.Errorf("metadata=true should be fuzzy-reconciled")
	}
	// Non-bool value must not be treated as truthy.
	if isFuzzyReconciled(output.PackageRef{Metadata: map[string]any{"bomly.diff.fuzzy_reconciled": "yes"}}) {
		t.Errorf("non-bool metadata should not be fuzzy-reconciled")
	}
}

// ---- isVulnerabilityFinding (kind classification) --------------------------

func TestIsVulnerabilityFinding_KindFirstThenFallback(t *testing.T) {
	cases := []struct {
		name string
		f    output.AuditFinding
		want bool
	}{
		{"Kind=vulnerability", output.AuditFinding{Kind: "vulnerability"}, true},
		{"Kind=vuln", output.AuditFinding{Kind: "vuln"}, true},
		{"Kind=advisory", output.AuditFinding{Kind: "advisory"}, true},
		{"Kind=cve", output.AuditFinding{Kind: "cve"}, true},
		{"Kind=policy", output.AuditFinding{Kind: "policy"}, false},
		{"Kind=risk", output.AuditFinding{Kind: "risk"}, false},
		{"Kind=license", output.AuditFinding{Kind: "license"}, false},
		// Fallback path when Kind is empty:
		{"empty Kind, CVE id", output.AuditFinding{ID: "CVE-2024-0001"}, true},
		{"empty Kind, GHSA id", output.AuditFinding{ID: "GHSA-abcd"}, true},
		{"empty Kind, OSV src", output.AuditFinding{Source: "osv"}, true},
		{"empty Kind, grype src", output.AuditFinding{Source: "grype"}, true},
		{"empty Kind, policy src", output.AuditFinding{Source: "policy"}, false},
		{"empty Kind, no signal", output.AuditFinding{ID: "X-1"}, false},
	}
	for _, tc := range cases {
		if got := isVulnerabilityFinding(tc.f); got != tc.want {
			t.Errorf("%s: isVulnerabilityFinding = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---- classifyRelationships -------------------------------------------------

func TestClassifyRelationships(t *testing.T) {
	// Build: root1 -> child1 -> grandchild1; root2 (no children).
	g := sdk.New()
	root1 := sdk.NewDependencyRef("root1", "1")
	root2 := sdk.NewDependencyRef("root2", "1")
	child := sdk.NewDependencyRef("child", "1")
	grandchild := sdk.NewDependencyRef("grandchild", "1")
	for _, p := range []*sdk.Dependency{root1, root2, child, grandchild} {
		if err := g.AddNode(p); err != nil {
			t.Fatalf("add %s: %v", p.ID, err)
		}
	}
	if err := g.AddEdge(root1.ID, child.ID); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddEdge(child.ID, grandchild.ID); err != nil {
		t.Fatalf("add dep: %v", err)
	}

	rels := classifyRelationships(g)
	if got := rels[root1.ID]; got != "root" {
		t.Errorf("root1 -> %q, want root", got)
	}
	if got := rels[root2.ID]; got != "root" {
		t.Errorf("root2 -> %q, want root", got)
	}
	if got := rels[child.ID]; got != "direct" {
		t.Errorf("child -> %q, want direct", got)
	}
	if got := rels[grandchild.ID]; got != "transitive" {
		t.Errorf("grandchild -> %q, want transitive", got)
	}
}

// ---- diffVulnTotal / diffVulnCount ----------------------------------------

func TestDiffVulnTotalAndCount(t *testing.T) {
	p := fixtureDiffPayload()

	// All vuln-kind findings = 3 (intro 1 + persisted 1 + resolved 1).
	if got := diffVulnTotal(p); got != 3 {
		t.Errorf("diffVulnTotal = %d, want 3", got)
	}
	if got := diffVulnCount(p, "introduced"); got != 1 {
		t.Errorf("diffVulnCount(introduced) = %d, want 1", got)
	}
	if got := diffVulnCount(p, "persisted"); got != 1 {
		t.Errorf("diffVulnCount(persisted) = %d, want 1", got)
	}
	if got := diffVulnCount(p, "resolved"); got != 1 {
		t.Errorf("diffVulnCount(resolved) = %d, want 1", got)
	}
	if got := diffVulnCount(p, "nonsense"); got != 0 {
		t.Errorf("diffVulnCount(nonsense) = %d, want 0", got)
	}

	// No audit → 0 across the board.
	empty := output.DiffResponse{}
	if got := diffVulnTotal(empty); got != 0 {
		t.Errorf("diffVulnTotal(empty) = %d, want 0", got)
	}
}

// ---- collectComponentChanges ----------------------------------------------

func TestCollectComponentChanges_FlattensWithStatusAndSeverity(t *testing.T) {
	m := newFixtureDiffModel()
	changes := m.collectComponentChanges()

	// 2 added + 2 changed + 1 removed = 5 flat entries.
	if got, want := len(changes), 5; got != want {
		t.Fatalf("collectComponentChanges returned %d entries, want %d", got, want)
	}

	statusCounts := map[string]int{}
	for _, c := range changes {
		statusCounts[c.status]++
	}
	if statusCounts["added"] != 2 {
		t.Errorf("added entries = %d, want 2", statusCounts["added"])
	}
	if statusCounts["changed"] != 2 {
		t.Errorf("changed entries = %d, want 2", statusCounts["changed"])
	}
	if statusCounts["removed"] != 1 {
		t.Errorf("removed entries = %d, want 1", statusCounts["removed"])
	}

	// The changed react package should carry maxSeverity="high" via its
	// attached Vulnerabilities? In our fixture it doesn't carry Vulnerabilities
	// inline, only via Audit findings — so maxSeverity is "". This is the
	// intended behavior: severity filter operates on PackageRef.Vulnerabilities,
	// not on audit findings.
	for _, c := range changes {
		if c.pkgRef.Name == "react" && c.status == "changed" && c.maxSeverity != "" {
			t.Errorf("react change carries no inline vuln, expected empty maxSeverity, got %q", c.maxSeverity)
		}
	}
}

func TestCollectComponentChanges_MaxSeverityFromInlineVulns(t *testing.T) {
	// Add a package with inline Vulnerabilities of mixed severity; the highest
	// should win.
	payload := output.DiffResponse{Results: output.DiffResults{Manifests: []output.DiffManifestResult{{
		Status: "changed", Path: "p", Ecosystem: "npm",
		Added: []output.DiffPackageChange{{Package: output.PackageRef{
			Name: "vulny", Version: "1",
			Vulnerabilities: []output.VulnerabilityRef{
				{ID: "X-1", Severity: "low"},
				{ID: "X-2", Severity: "critical"},
				{ID: "X-3", Severity: "high"},
			},
		}}},
	}}}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	changes := m.collectComponentChanges()
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if got, want := changes[0].maxSeverity, "critical"; got != want {
		t.Errorf("maxSeverity = %q, want %q", got, want)
	}
}

// ---- findingsTableLines (right-column Overview tables) --------------------

func TestFindingsTableLines_VulnerabilityFromFixture(t *testing.T) {
	stats := newFixtureDiffModel().computeOverviewStats()
	lines := findingsTableLines("Severity", severityRowKeys(), stats.vulnByStatus, severityRowColor, 60)
	plain := render.StripANSI(strings.Join(lines, "\n"))

	// Header must include all four columns. The audit-delta columns use
	// the short new/old/fixed labels everywhere in the diff TUI.
	for _, col := range []string{"Severity", "New", "Old", "Fixed"} {
		if !strings.Contains(plain, col) {
			t.Errorf("header missing column %q in:\n%s", col, plain)
		}
	}
	// Every severity row must appear (even zero rows) so the layout is
	// stable across diffs.
	for _, row := range []string{"Critical", "High", "Medium", "Low", "Unknown"} {
		if !strings.Contains(plain, row) {
			t.Errorf("expected severity row %q in:\n%s", row, plain)
		}
	}
	// Total row is the implicit gut-check footer.
	if !strings.Contains(plain, "Total") {
		t.Errorf("expected Total footer row in:\n%s", plain)
	}
}

func TestFindingsTableLines_KeepsZeroRowsForStableLayout(t *testing.T) {
	// An audit with zero findings of any kind must still render the full
	// severity table — the user expects the layout to be present even
	// when the diff is clean.
	m := NewDiff(output.DiffResponse{Audit: &output.DiffAudit{}}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	stats := m.computeOverviewStats()
	lines := findingsTableLines("Severity", severityRowKeys(), stats.vulnByStatus, severityRowColor, 60)
	plain := render.StripANSI(strings.Join(lines, "\n"))
	for _, row := range []string{"Critical", "High", "Medium", "Low", "Unknown", "Total"} {
		if !strings.Contains(plain, row) {
			t.Errorf("zero-finding table missing row %q in:\n%s", row, plain)
		}
	}
}

func TestFindingsTableLines_PackageOtherRowAbsorbsUnknownRules(t *testing.T) {
	// External plugin emits a package-kind finding whose rule we don't
	// recognize. computeOverviewStats must funnel it into the "Other"
	// row so the pre-seeded table stays exhaustive.
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "ext:mystery:pkg@1", Kind: "package", Auditor: "external"},
		},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	stats := m.computeOverviewStats()
	if got := stats.packageByStatus["other"]["introduced"]; got != 1 {
		t.Errorf("packageByStatus[other][introduced] = %d, want 1", got)
	}
	plain := render.StripANSI(strings.Join(findingsTableLines("Rule", packageRuleRowKeys(), stats.packageByStatus, ruleRowColor, 60), "\n"))
	if !strings.Contains(plain, "Other") {
		t.Errorf("Other row should appear in the package table, got:\n%s", plain)
	}
}

// ---- overviewHeadline ------------------------------------------------------

// TestOverviewHeadline_FailReflectsIntroducedDisposition: the audit chip
// reads FailingIntroduced (introduced findings whose Disposition gates
// the exit code). The fixture has 2 introduced findings, both with the
// default empty Disposition, so both count as failing → "Audit FAIL (2
// introduced, exit 2)".
func TestOverviewHeadline_FailReflectsIntroducedDisposition(t *testing.T) {
	m := newFixtureDiffModel()
	plain := render.StripANSI(m.overviewHeadline(200))
	for _, want := range []string{
		"5 package changes",
		"1 new vulnerabilities", // count of vuln-kind in Introduced
		"Audit FAIL (2 new, exit 2)",
		"1 fuzzy-reconciled",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("headline missing %q in: %q", want, plain)
		}
	}
}

func TestOverviewHeadline_PassWhenNoIntroduced(t *testing.T) {
	p := fixtureDiffPayload()
	p.Audit = &output.DiffAudit{AuditSummary: &output.AuditSummary{Total: 0}}
	m := NewDiff(p, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := render.StripANSI(m.overviewHeadline(200))
	if !strings.Contains(plain, "Audit PASS (exit 0)") {
		t.Errorf("headline expected Audit PASS, got: %q", plain)
	}
}

// Resolved findings on their own do not flip the verdict to FAIL —
// regression for diff_cmd.go's new gate (Introduced only).
func TestOverviewHeadline_ResolvedOnlyIsPass(t *testing.T) {
	p := output.DiffResponse{Audit: &output.DiffAudit{
		Resolved:     []output.AuditFinding{{ID: "CVE-2022-X", Kind: "vulnerability", Severity: "high"}},
		AuditSummary: &output.AuditSummary{},
	}}
	m := NewDiff(p, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := render.StripANSI(m.overviewHeadline(200))
	if !strings.Contains(plain, "Audit PASS") {
		t.Errorf("resolved-only headline expected PASS, got: %q", plain)
	}
	if strings.Contains(plain, "FAIL") {
		t.Errorf("resolved-only headline must not contain FAIL, got: %q", plain)
	}
}

// Warn-only introduced findings pass policy but the chip surfaces the
// count so the user knows findings exist.
func TestOverviewHeadline_WarnOnlyIntroducedIsPassWithCount(t *testing.T) {
	p := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "W-1", Disposition: string(sdk.FindingDispositionWarn)},
			{ID: "W-2", Disposition: string(sdk.FindingDispositionWarn)},
		},
		AuditSummary: &output.AuditSummary{Total: 2},
	}}
	m := NewDiff(p, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := render.StripANSI(m.overviewHeadline(200))
	if !strings.Contains(plain, "Audit PASS (2 warn-only, exit 0)") {
		t.Errorf("warn-only headline expected 'Audit PASS (2 warn-only, exit 0)', got: %q", plain)
	}
}

func TestOverviewHeadline_NotEvaluatedWhenAuditMissing(t *testing.T) {
	p := fixtureDiffPayload()
	p.Audit = nil
	m := NewDiff(p, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := render.StripANSI(m.overviewHeadline(200))
	if !strings.Contains(plain, "Audit not run") {
		t.Errorf("headline expected 'Audit not run', got: %q", plain)
	}
}

// ---- audit-status label rename + dedupe ----------------------------------

// TestAuditStatusLabel maps the internal audit-delta status strings to
// their short UI labels. Locks in the user-facing vocabulary so a future
// refactor doesn't accidentally reintroduce "introduced/persisted/resolved"
// in the diff TUI.
func TestAuditStatusLabel(t *testing.T) {
	cases := []struct{ in, want, title string }{
		{"introduced", "new", "New"},
		{"persisted", "old", "Old"},
		{"resolved", "fixed", "Fixed"},
		// Other words pass through untouched (lowercased).
		{"added", "added", "Added"},
		{"retired", "retired", "Retired"},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := auditStatusLabel(tc.in); got != tc.want {
			t.Errorf("auditStatusLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := auditStatusTitle(tc.in); got != tc.title {
			t.Errorf("auditStatusTitle(%q) = %q, want %q", tc.in, got, tc.title)
		}
	}
}

// TestComponentChangeBadges_NoDuplicateStatus asserts the deduplication.
// The row's subtitle already renders a colored status badge (via
// statusBadge) so componentChangeBadges must NOT prepend another badge
// whose label is the same status string — that double-coding was the bug
// the user flagged on the Components tab.
func TestComponentChangeBadges_NoDuplicateStatus(t *testing.T) {
	c := flatComponentChange{
		status:       "changed",
		maxSeverity:  "high",
		relationship: "direct",
	}
	for _, b := range componentChangeBadges(c) {
		if strings.EqualFold(b.label, "changed") {
			t.Errorf("componentChangeBadges leaked a duplicate %q badge: %+v", b.label, componentChangeBadges(c))
		}
	}
}

// TestAuditDeltaBadges_NoDuplicateStatus is the symmetric guarantee for
// the Vulnerabilities and Findings tabs: severity becomes a badge, but
// the status (introduced/persisted/resolved) lives only in the subtitle
// so it isn't shown twice.
func TestAuditDeltaBadges_NoDuplicateStatus(t *testing.T) {
	d := auditDelta{status: "introduced", severity: "high"}
	for _, b := range auditDeltaBadges(d) {
		if strings.EqualFold(b.label, "introduced") || strings.EqualFold(b.label, "new") {
			t.Errorf("auditDeltaBadges leaked a duplicate status badge: %+v", auditDeltaBadges(d))
		}
	}
}

// TestStatusBadge_NewOldFixed colors the renamed audit-delta labels so
// they read at a glance. Both the short ("new"/"old"/"fixed") and the
// legacy long forms ("introduced"/"persisted"/"resolved") render the
// same colored badge — the long forms route through auditStatusLabel
// internally and recurse.
func TestStatusBadge_NewOldFixed(t *testing.T) {
	for _, status := range []string{"new", "old", "fixed", "introduced", "persisted", "resolved", "retired"} {
		got := render.StripANSI(statusBadge(status))
		// Badge text is the uppercased *display* label. Long forms must
		// translate; short forms are emitted verbatim.
		want := strings.ToUpper(auditStatusLabel(status))
		if !strings.Contains(got, want) {
			t.Errorf("statusBadge(%q) = %q, want it to contain %q", status, got, want)
		}
	}
}

// TestDistributionLine_PreservesLongCompositeLabels guards against the
// truncation bug on the Overview's per-relationship/per-scope panes,
// where "1 changed runtime (100%)" used to get clipped to "1 changed
// runtime (1...". The label area now scales with the pane width.
func TestDistributionLine_PreservesLongCompositeLabels(t *testing.T) {
	counts := map[string]int{
		"changed runtime":   7,
		"removed unknown":   18,
		"added development": 3,
	}
	// Width corresponds to a typical right-column pane in a 120-col TTY.
	lines := coloredDistributionLines(counts, 28, len(counts), 58)
	plain := render.StripANSI(strings.Join(lines, "\n"))
	for _, want := range []string{
		"7 changed runtime (",
		"18 removed unknown (",
		"3 added development (",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("distribution truncates %q in:\n%s", want, plain)
		}
	}
	// Percentages must be fully present (no "..." swallowing the closing
	// paren).
	for _, want := range []string{"(25%)", "(64%)", "(10%)"} {
		if !strings.Contains(plain, want) {
			t.Errorf("distribution drops percentage %q in:\n%s", want, plain)
		}
	}
}

// TestDistributionLine_FitsBoxBudget catches the regression where the
// rendered line was longer than the box content area, causing boxView
// to clip the bar tail. distributionLine receives `width` from a caller
// that passes `paneWidth-2`; boxView then reserves another 2 cols for
// horizontal padding. So every produced line must have at most
// `width - 2` *visible* (ANSI-stripped) columns. Anything longer means
// the bar (or label) will end with "..." inside the box.
func TestDistributionLine_FitsBoxBudget(t *testing.T) {
	for _, width := range []int{32, 40, 58, 72, 100, 140} {
		counts := map[string]int{"go": 22, "npm": 5, "python": 1}
		for _, line := range coloredDistributionLines(counts, 28, len(counts), width) {
			visible := len([]rune(render.StripANSI(line)))
			if visible > width-2 {
				t.Errorf("distribution line at width=%d has %d visible cols, want <= %d.\nLine: %q",
					width, visible, width-2, render.StripANSI(line))
			}
		}
	}
}

// ---- Findings tab outcome panels ------------------------------------------

// TestFindingsOutcomePanels_BucketsCoverAllKinds: now that the Findings
// tab spans every FindingKind, the Findings Delta panel must show the
// run-level introduced/persisted/resolved totals (not just non-vuln).
// Fixture has:
//
//	Introduced: 1 vuln + 1 license
//	Persisted:  1 vuln
//	Resolved:   1 vuln
//
// Sum should be 2/1/1 — agreeing with the rows shown in the list below
// and with AuditSummary.
func TestFindingsOutcomePanels_BucketsCoverAllKinds(t *testing.T) {
	panels := newFixtureDiffModel().findingsOutcomePanels()
	plain := stripPanels(panels)

	if !strings.Contains(plain, "Findings Delta") {
		t.Fatalf("expected 'Findings Delta' panel, got:\n%s", plain)
	}
	for _, want := range []string{"2 New", "1 Old", "1 Fixed"} {
		if !strings.Contains(plain, want) {
			t.Errorf("findings outcome buckets missing %q (must cover all kinds), got:\n%s", want, plain)
		}
	}
	// By Kind panel reflects the per-kind split.
	for _, want := range []string{"3 vulnerability", "1 license"} {
		if !strings.Contains(plain, want) {
			t.Errorf("By Kind missing %q, got:\n%s", want, plain)
		}
	}
}

// TestFindingsOutcomePanels_SpansAllKinds verifies the refactor that
// promoted the Findings tab from "non-vuln only" to "every FindingKind".
// In this scenario:
//
//	Introduced: 6 vulns (all failing) + 0 license + 0 package
//	Persisted:  0 vulns + 6 license + 0 package
//
// The Findings tab's outcome panel now reflects the full run (matching
// the Vulnerabilities tab's contribution too), and the By Kind panel
// shows vulnerability + license + package counts.
func TestFindingsOutcomePanels_SpansAllKinds(t *testing.T) {
	var intro []output.AuditFinding
	for i := 0; i < 6; i++ {
		intro = append(intro, output.AuditFinding{
			ID:       "CVE-X-" + string(rune('A'+i)),
			Kind:     "vulnerability",
			Auditor:  "vulnerability",
			Source:   "osv",
			Severity: "high",
		})
	}
	var persisted []output.AuditFinding
	for i := 0; i < 6; i++ {
		persisted = append(persisted, output.AuditFinding{
			ID:       "license:unknown-license:pkg-" + string(rune('A'+i)),
			Kind:     string(sdk.FindingKindLicense),
			Auditor:  "license",
			Source:   "license",
			Severity: "unknown",
		})
	}
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced:   intro,
		Persisted:    persisted,
		AuditSummary: &output.AuditSummary{High: 6, Total: 12},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := stripPanels(m.findingsOutcomePanels())

	// FAIL reflects all 6 introduced vulnerabilities (now that vulns are
	// in scope on this tab too).
	if !strings.Contains(plain, " FAIL ") {
		t.Errorf("expected Findings tab to surface FAIL when there are introduced vulns, got:\n%s", plain)
	}
	if !strings.Contains(plain, "6 new finding(s) gate exit code") {
		t.Errorf("expected '6 new finding(s) gate exit code', got:\n%s", plain)
	}
	if !strings.Contains(plain, "6 vuln + 0 license/package") {
		t.Errorf("expected explainer mentioning 6 vuln + 0 license/package, got:\n%s", plain)
	}
	// Findings Delta: 6 new + 6 old + 0 fixed (all kinds).
	for _, want := range []string{"6 New", "6 Old", "0 Fixed"} {
		if !strings.Contains(plain, want) {
			t.Errorf("Findings Delta missing %q in:\n%s", want, plain)
		}
	}
	// By Kind: vulnerabilities AND license counts both show up.
	for _, want := range []string{"6 vulnerability", "6 license"} {
		if !strings.Contains(plain, want) {
			t.Errorf("By Kind panel missing %q in:\n%s", want, plain)
		}
	}
}

// TestFindingsOutcomePanels_PassWhenOnlyResolvedAndPersisted locks in the
// happy path: no introduced findings of any kind → PASS, exit code 0.
func TestFindingsOutcomePanels_PassWhenNoIntroduced(t *testing.T) {
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Persisted: []output.AuditFinding{
			{ID: "CVE-1", Kind: "vulnerability", Auditor: "vulnerability"},
		},
		Resolved: []output.AuditFinding{
			{ID: "license:denied-license:pkg@1", Kind: "license", Auditor: "license"},
		},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := stripPanels(m.findingsOutcomePanels())
	if !strings.Contains(plain, " PASS ") {
		t.Errorf("expected PASS verdict with no introduced findings, got:\n%s", plain)
	}
	if !strings.Contains(plain, "Exit code 0 (clean)") {
		t.Errorf("expected 'Exit code 0 (clean)', got:\n%s", plain)
	}
}

// TestVulnsOutcomePanels_ScopedToVulns is the symmetric guarantee for
// the Vulnerabilities tab — outcome counts come from vuln-only buckets,
// with a run-level breadcrumb mentioning policy too.
func TestVulnsOutcomePanels_ScopedToVulns(t *testing.T) {
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "CVE-1", Kind: "vulnerability", Auditor: "vulnerability", Source: "osv", Severity: "critical"},
			{ID: "license:unknown-license:pkg@1", Kind: string(sdk.FindingKindLicense), Auditor: "license", Source: "license", Severity: "unknown"},
		},
		Persisted: []output.AuditFinding{
			{ID: "CVE-2", Kind: "vulnerability", Auditor: "vulnerability", Source: "osv", Severity: "medium"},
		},
		AuditSummary: &output.AuditSummary{Critical: 1, Medium: 1, Total: 3},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := stripPanels(m.vulnsOutcomePanels())

	// FAIL verdict reflects the 1 introduced vuln.
	if !strings.Contains(plain, " FAIL ") {
		t.Errorf("Vulns tab outcome should be FAIL, got:\n%s", plain)
	}
	if !strings.Contains(plain, "1 new vulnerability(ies) gate exit code") {
		t.Errorf("expected vuln-scoped failing count, got:\n%s", plain)
	}
	// Vuln Deltas: 1/1/0 (vuln-only, not 2/1/0).
	for _, want := range []string{"1 New", "1 Old", "0 Fixed"} {
		if !strings.Contains(plain, want) {
			t.Errorf("Vuln Deltas missing %q in:\n%s", want, plain)
		}
	}
	// By Severity scoped to vuln-kind: 1 critical + 1 medium, no "unknown"
	// row (POL-1's severity must not leak in).
	if !strings.Contains(plain, "1 Critical") {
		t.Errorf("expected '1 Critical' in severity panel, got:\n%s", plain)
	}
	if !strings.Contains(plain, "1 Medium") {
		t.Errorf("expected '1 Medium' in severity panel, got:\n%s", plain)
	}
	if strings.Contains(plain, "1 Unknown") {
		t.Errorf("severity panel must not leak POL-1's 'unknown' severity, got:\n%s", plain)
	}
	// Run-level breadcrumb mentions BOTH kinds (vuln + license/package).
	if !strings.Contains(plain, "1 vuln + 1 policy") {
		t.Errorf("expected run-level breadcrumb mentioning both kinds, got:\n%s", plain)
	}
}

// TestVulnsOutcomePanels_NotEvaluated locks in the empty-state.
func TestVulnsOutcomePanels_NotEvaluated(t *testing.T) {
	m := NewDiff(output.DiffResponse{}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := stripPanels(m.vulnsOutcomePanels())
	if !strings.Contains(plain, " NOT EVALUATED ") {
		t.Errorf("expected NOT EVALUATED outcome, got:\n%s", plain)
	}
	if !strings.Contains(plain, "to evaluate vulnerabilities") {
		t.Errorf("expected vuln-flavored helper text, got:\n%s", plain)
	}
}

// TestAuditVerdict_FailingSplitByKind verifies that the split fields used
// by the per-tab outcome panels are populated correctly.
func TestAuditVerdict_FailingSplitByKind(t *testing.T) {
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			// 2 failing vulns (empty Disposition = fail).
			{ID: "CVE-1", Kind: "vulnerability", Auditor: "vulnerability"},
			{ID: "CVE-2", Kind: "vulnerability", Auditor: "vulnerability", Disposition: string(sdk.FindingDispositionFail)},
			// 1 warn vuln — counted in WarnIntroduced, not FailingIntroduced*.
			{ID: "CVE-3", Kind: "vulnerability", Auditor: "vulnerability", Disposition: string(sdk.FindingDispositionWarn)},
			// 1 failing license-kind finding.
			{ID: "license:denied-license:pkg@1", Kind: string(sdk.FindingKindLicense), Auditor: "license"},
			// 1 warn license-kind finding.
			{ID: "license:unknown-license:pkg@2", Kind: string(sdk.FindingKindLicense), Auditor: "license", Disposition: string(sdk.FindingDispositionWarn)},
		},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	v := m.auditVerdict()
	if v.FailingIntroduced != 3 {
		t.Errorf("FailingIntroduced = %d, want 3", v.FailingIntroduced)
	}
	if v.FailingIntroducedVuln != 2 {
		t.Errorf("FailingIntroducedVuln = %d, want 2", v.FailingIntroducedVuln)
	}
	if v.FailingIntroducedNonVuln != 1 {
		t.Errorf("FailingIntroducedNonVuln = %d, want 1", v.FailingIntroducedNonVuln)
	}
	if v.WarnIntroduced != 2 {
		t.Errorf("WarnIntroduced = %d, want 2", v.WarnIntroduced)
	}
}

func TestFindingsOutcomePanels_ByKindReadsFindingKind(t *testing.T) {
	// The "By Kind" panel must split by AuditFinding.Kind (the actual
	// FindingKind), NOT by Auditor name. Build a payload that exercises
	// every kind so we can see all three rows.
	payload := output.DiffResponse{Audit: &output.DiffAudit{
		Introduced: []output.AuditFinding{
			{ID: "CVE-1", Kind: "vulnerability", Auditor: "vulnerability", Source: "osv"},
			{ID: "license:unknown-license:pkg@1", Kind: "license", Auditor: "license", Source: "license"},
			{ID: "license:invalid-license:pkg@2", Kind: "license", Auditor: "license", Source: "license"},
			{ID: "package:denied-package:pkg@3", Kind: "package", Auditor: "package", Source: "package"},
		},
		AuditSummary: &output.AuditSummary{Total: 4},
	}}
	m := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	plain := stripPanels(m.findingsOutcomePanels())

	if !strings.Contains(plain, "By Kind") {
		t.Fatalf("expected 'By Kind' panel, got:\n%s", plain)
	}
	for _, want := range []string{"1 vulnerability", "2 license", "1 package"} {
		if !strings.Contains(plain, want) {
			t.Errorf("By Kind panel missing %q, got:\n%s", want, plain)
		}
	}
}

// ---- Findings tab grouping axis -------------------------------------------

func TestNextFindingGroup_CyclesStatusKindPackage(t *testing.T) {
	// Severity is intentionally excluded from the Findings axis — license
	// and package auditors emit Severity="unknown" for everything, so
	// "severity" grouping is degenerate. Lock that exclusion in.
	cases := []struct{ in, want string }{
		{"status", "kind"},
		{"kind", "package"},
		{"package", "status"},
		{"", "status"},
	}
	for _, tc := range cases {
		if got := nextFindingGroup(tc.in); got != tc.want {
			t.Errorf("nextFindingGroup(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- License-tab category & recognition keys ------------------------------

func TestLicenseGroupKey_CategoryAndRecognition(t *testing.T) {
	cases := []struct {
		license            string
		wantCategory       string // licenseGroupKeyDiff(... "category")
		wantRecognitionKey string // licenseGroupKeyDiff(... "recognition")
	}{
		{"MIT", "permissive", "recognized"},
		{"Apache-2.0", "permissive", "recognized"},
		{"GPL-3.0-only", "copyleft", "recognized"},
		{"LGPL-2.1", "copyleft", "recognized"},
		{"", "unknown", "unknown"},
		// looksLikeSPDXLicense treats any value containing "-" as SPDX-like,
		// so to cover the "unrecognized" branch we need a free-text license
		// without a hyphen, parens, or spaces.
		{"Proprietary", "unclassified", "unrecognized"},
	}
	for _, tc := range cases {
		d := licenseDelta{license: tc.license, status: "introduced"}
		if got := licenseGroupKeyDiff(d, "category"); got != tc.wantCategory {
			t.Errorf("licenseGroupKeyDiff(%q, category) = %q, want %q", tc.license, got, tc.wantCategory)
		}
		if got := licenseGroupKeyDiff(d, "recognition"); got != tc.wantRecognitionKey {
			t.Errorf("licenseGroupKeyDiff(%q, recognition) = %q, want %q", tc.license, got, tc.wantRecognitionKey)
		}
	}
}

func TestNextLicenseGroup_CyclesAllFiveAxes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"license", "status"},
		{"status", "manifest"},
		{"manifest", "category"},
		{"category", "recognition"},
		{"recognition", "license"},
		{"", "license"},
	}
	for _, tc := range cases {
		if got := nextLicenseGroup(tc.in); got != tc.want {
			t.Errorf("nextLicenseGroup(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- Detector lookup ------------------------------------------------------

func TestDetectorForManifest_LooksUpInBothGraphs(t *testing.T) {
	// Build a consolidated graph that knows about manifest "go.mod"
	// detected by "gomod-detector". Whether it's on the head side or
	// the base side, lookupDetector must find it.
	g := sdk.New()
	head := sdk.ConsolidatedGraph{
		Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"}),
		Manifests: []sdk.ConsolidatedManifest{{
			Entry:        sdk.GraphEntry{Manifest: sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"}},
			Subproject:   sdk.Subproject{RelativePath: "."},
			DetectorName: "gomod-detector",
		}},
	}
	base := sdk.ConsolidatedGraph{
		Graphs: sdk.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package.json", Kind: "package-lock.json"}),
		Manifests: []sdk.ConsolidatedManifest{{
			Entry:        sdk.GraphEntry{Manifest: sdk.ManifestMetadata{Path: "package.json", Kind: "package-lock.json"}},
			Subproject:   sdk.Subproject{RelativePath: "web/"},
			DetectorName: "npm-detector",
		}},
	}
	m := NewDiff(output.DiffResponse{}, base, head)

	headMf := output.DiffManifestResult{Path: "go.mod", Subproject: "."}
	if got := m.detectorForManifest(headMf); got != "gomod-detector" {
		t.Errorf("detectorForManifest(go.mod) = %q, want gomod-detector", got)
	}
	// Base-only manifest still resolves — important because removed
	// manifests live exclusively on the base side.
	baseMf := output.DiffManifestResult{Path: "package.json", Subproject: "web/"}
	if got := m.detectorForManifest(baseMf); got != "npm-detector" {
		t.Errorf("detectorForManifest(package.json) = %q, want npm-detector", got)
	}
	// Unknown manifest → empty string (rendered as "-" by valueOrDash).
	unknownMf := output.DiffManifestResult{Path: "Cargo.toml"}
	if got := m.detectorForManifest(unknownMf); got != "" {
		t.Errorf("detectorForManifest(Cargo.toml) = %q, want empty", got)
	}
}

// ---- componentChangeDetails before/after deltas ---------------------------

func TestComponentChangeDetails_ChangedShowsLicenseAndVulnDelta(t *testing.T) {
	c := flatComponentChange{
		manifest:     output.DiffManifestResult{Path: "go.mod", Ecosystem: "go"},
		manifestName: "go.mod",
		ecosystem:    "go",
		status:       "changed",
		pkgName:      "react",
		beforeVer:    "18.2.0",
		afterVer:     "19.0.0",
		relationship: "direct",
		beforePkg: output.PackageRef{
			Name: "react", Version: "18.2.0",
			Licenses:        []output.LicenseRef{{SPDXExpression: "MIT"}, {SPDXExpression: "BSD-2-Clause"}},
			Vulnerabilities: []output.VulnerabilityRef{{ID: "CVE-OLD", Severity: "high"}},
		},
		pkgRef: output.PackageRef{
			Name: "react", Version: "19.0.0",
			Licenses:        []output.LicenseRef{{SPDXExpression: "MIT"}, {SPDXExpression: "Apache-2.0"}},
			Vulnerabilities: []output.VulnerabilityRef{{ID: "CVE-NEW", Severity: "critical"}},
		},
	}
	plain := render.StripANSI(strings.Join(componentChangeDetails(c), "\n"))

	// Version delta visible.
	for _, want := range []string{"Before: 18.2.0", "After:  19.0.0"} {
		if !strings.Contains(plain, want) {
			t.Errorf("componentChangeDetails missing %q in:\n%s", want, plain)
		}
	}
	// License delta visible: MIT unchanged, BSD-2-Clause retired, Apache-2.0 new.
	// Labels follow the new/old/fixed nomenclature used elsewhere in the diff TUI.
	for _, want := range []string{
		"Licenses (before → after)",
		"MIT", "(unchanged)",
		"BSD-2-Clause", "(retired)",
		"Apache-2.0", "(new)",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("license delta section missing %q in:\n%s", want, plain)
		}
	}
	// Vulnerability delta visible: CVE-OLD fixed, CVE-NEW new.
	for _, want := range []string{
		"Vulnerabilities (before → after)",
		"CVE-OLD", "(fixed)",
		"CVE-NEW", "(new)",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("vuln delta section missing %q in:\n%s", want, plain)
		}
	}
	// Relationship is present in identity section.
	if !strings.Contains(plain, "Relationship: direct") {
		t.Errorf("expected 'Relationship: direct' in identity section, got:\n%s", plain)
	}
}

func TestComponentChangeDetails_AddedRemovedShowsPlainLists(t *testing.T) {
	added := flatComponentChange{
		manifest: output.DiffManifestResult{Path: "go.mod", Ecosystem: "go"},
		status:   "added", pkgName: "new-thing", relationship: "transitive",
		pkgRef: output.PackageRef{
			Name: "new-thing", Version: "1",
			Licenses:        []output.LicenseRef{{SPDXExpression: "ISC"}},
			Vulnerabilities: []output.VulnerabilityRef{{ID: "CVE-X", Severity: "low"}},
		},
	}
	plain := render.StripANSI(strings.Join(componentChangeDetails(added), "\n"))

	// Added packages show plain Licenses and Vulnerabilities sections,
	// NOT the "(before → after)" delta form.
	if strings.Contains(plain, "(before → after)") {
		t.Errorf("added package should not render before/after delta sections, got:\n%s", plain)
	}
	for _, want := range []string{
		"Licenses",
		"- ISC",
		"Vulnerabilities",
		"CVE-X",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("added-package details missing %q in:\n%s", want, plain)
		}
	}
}

// stripPanels concatenates every panel's title + lines into a single
// ANSI-stripped string for substring assertions.
func stripPanels(panels []listPanel) string {
	var b strings.Builder
	for _, p := range panels {
		b.WriteString(p.title)
		b.WriteString("\n")
		for _, l := range p.lines {
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	return render.StripANSI(b.String())
}
