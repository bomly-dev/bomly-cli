package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func newTestScorecardTUI(repo string, score float64, checks ...sdk.PackageScorecardCheck) *sdk.PackageScorecard {
	return &sdk.PackageScorecard{
		Source:           "api.scorecard.dev",
		Repository:       repo,
		CommitSHA:        "abc",
		ScorecardVersion: "v5.0.0",
		RunDate:          time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC),
		AggregateScore:   score,
		Checks:           checks,
	}
}

func TestPostureTab_ScanRendersList(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	dep := sdk.NewPackage(sdk.Package{Name: "lib", Version: "1.0.0", Scope: "runtime"})
	dep.Scorecard = newTestScorecardTUI("github.com/example/lib", 3.5,
		sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 2, Reason: "branch protection disabled"},
		sdk.PackageScorecardCheck{Name: "Code-Review", Score: 7, Reason: "most changes reviewed"},
	)
	for _, pkg := range []*sdk.Package{root, dep} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:    ".",
			PrimaryDetector: "npm-detector",
			Ecosystem:       sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithEnrichEnabled(true)
	model.SelectView(6) // Posture is the 6th tab (1-indexed: Overview, Components, Vulns, Licenses, Findings, Posture, Source)

	plain := render.StripANSI(model.View(160, 40))
	for _, want := range []string{
		"Posture",
		"Repositories (1)",
		"github.com/example/lib",
		"3.5/10",
		"Repository Posture", // details pane title
		"Branch-Protection",  // lowest-scoring check appears in details
		"branch protection disabled",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("posture view missing %q\n---\n%s", want, plain)
		}
	}
}

func TestPostureTab_ScanEmptyStateHints(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add package: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:    ".",
			PrimaryDetector: "npm-detector",
			Ecosystem:       sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithEnrichEnabled(true)
	model.SelectView(6)

	plain := render.StripANSI(model.View(160, 40))
	if !strings.Contains(plain, "--matchers +scorecard") {
		t.Errorf("expected empty state to hint at --matchers +scorecard; got:\n%s", plain)
	}
}

func TestPostureRowsFromGraph_DedupesAndSortsWorstFirst(t *testing.T) {
	g := sdk.New()
	low := sdk.NewPackage(sdk.Package{Name: "low", Version: "1"})
	low.Scorecard = newTestScorecardTUI("github.com/low/repo", 2.0)
	high := sdk.NewPackage(sdk.Package{Name: "high", Version: "1"})
	high.Scorecard = newTestScorecardTUI("github.com/high/repo", 9.0)
	mid := sdk.NewPackage(sdk.Package{Name: "mid", Version: "1"})
	mid.Scorecard = newTestScorecardTUI("github.com/mid/repo", 6.0)
	monoA := sdk.NewPackage(sdk.Package{Name: "a", Version: "1"})
	monoA.Scorecard = newTestScorecardTUI("github.com/mono/repo", 7.5)
	monoB := sdk.NewPackage(sdk.Package{Name: "b", Version: "1"})
	monoB.Scorecard = newTestScorecardTUI("github.com/mono/repo", 7.5)
	for _, pkg := range []*sdk.Package{low, high, mid, monoA, monoB} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	rows := postureRowsFromGraph(g)
	if len(rows) != 4 {
		t.Fatalf("expected 4 deduped repos, got %d: %+v", len(rows), rows)
	}
	if rows[0].repository != "github.com/low/repo" {
		t.Errorf("expected lowest-score repo first; got %q", rows[0].repository)
	}
	if rows[len(rows)-1].repository != "github.com/high/repo" {
		t.Errorf("expected highest-score repo last; got %q", rows[len(rows)-1].repository)
	}
	var mono *postureRow
	for i := range rows {
		if rows[i].repository == "github.com/mono/repo" {
			mono = &rows[i]
			break
		}
	}
	if mono == nil {
		t.Fatal("monorepo row missing")
	}
	if len(mono.packages) != 2 {
		t.Errorf("expected monorepo row to dedupe 2 packages; got %d", len(mono.packages))
	}
}

func TestPostureDiffRowsFromPayload_Classifies(t *testing.T) {
	results := output.DiffDependencyResults{
		Added: []output.DiffPackageChange{
			{Package: output.PackageRef{Name: "new", Scorecard: newTestScorecardTUI("github.com/new/repo", 7.5)}},
		},
		Removed: []output.DiffPackageChange{
			{Package: output.PackageRef{Name: "old", Scorecard: newTestScorecardTUI("github.com/old/repo", 4.0)}},
		},
		Changed: []output.DiffChangedPackage{
			{
				Before: output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 6.0)},
				After:  output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 8.5)},
			},
			{
				// Same score on both sides → unchanged
				Before: output.PackageRef{Name: "stable", Scorecard: newTestScorecardTUI("github.com/stable/repo", 9.0)},
				After:  output.PackageRef{Name: "stable", Scorecard: newTestScorecardTUI("github.com/stable/repo", 9.0)},
			},
		},
	}
	rows := postureDiffRowsFromPayload(results)
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(rows))
	}
	statuses := map[string]postureDiffStatus{}
	for _, row := range rows {
		statuses[row.repository] = row.status()
	}
	if statuses["github.com/new/repo"] != postureDiffStatusIntroduced {
		t.Errorf("new/repo = %s; want introduced", statuses["github.com/new/repo"])
	}
	if statuses["github.com/old/repo"] != postureDiffStatusDropped {
		t.Errorf("old/repo = %s; want dropped", statuses["github.com/old/repo"])
	}
	if statuses["github.com/shared/repo"] != postureDiffStatusChanged {
		t.Errorf("shared/repo = %s; want changed", statuses["github.com/shared/repo"])
	}
	if statuses["github.com/stable/repo"] != postureDiffStatusUnchanged {
		t.Errorf("stable/repo = %s; want unchanged", statuses["github.com/stable/repo"])
	}
}

func TestPostureTab_DiffRendersList(t *testing.T) {
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Changed: []output.DiffChangedPackage{{
					Before: output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 5.0)},
					After:  output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 8.0)},
				}},
				Added: []output.DiffPackageChange{{
					Package: output.PackageRef{Name: "new", Scorecard: newTestScorecardTUI("github.com/new/repo", 6.0)},
				}},
			},
		},
	}
	model := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	model.SelectView(6)

	plain := render.StripANSI(model.View(160, 40))
	for _, want := range []string{
		"Posture",
		"Repositories (2)",
		"github.com/shared/repo",
		"github.com/new/repo",
		"Posture Delta",
		"Biggest Score Movers",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("diff posture view missing %q\n---\n%s", want, plain)
		}
	}
}

func TestPostureScoreBand_BoundaryCases(t *testing.T) {
	cases := []struct {
		score float64
		band  string
	}{
		{-1, "inconclusive"},
		{0, "critical"},
		{2.9, "critical"},
		{3, "warning"},
		{5.9, "warning"},
		{6, "ok"},
		{7.9, "ok"},
		{8, "strong"},
		{10, "strong"},
	}
	for _, tc := range cases {
		if got := postureScoreBand(tc.score); got != tc.band {
			t.Errorf("postureScoreBand(%v) = %q, want %q", tc.score, got, tc.band)
		}
	}
}
