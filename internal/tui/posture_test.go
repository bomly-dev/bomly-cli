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
	root := sdk.NewDependencyRef("demo-app", "1.0.0")
	const libPURL = "pkg:npm/lib@1.0.0"
	dep := sdk.NewDependency(sdk.Dependency{Name: "lib", Version: "1.0.0", Scopes: sdk.ScopesOf(sdk.ScopeRuntime), PURL: libPURL})
	registry := sdk.NewPackageRegistry()
	regLib := registry.Ensure(libPURL)
	regLib.Name = "lib"
	regLib.Version = "1.0.0"
	regLib.Scorecard = newTestScorecardTUI("github.com/example/lib", 3.5,
		sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 2, Reason: "branch protection disabled"},
		sdk.PackageScorecardCheck{Name: "Code-Review", Score: 7, Reason: "most changes reviewed"},
	)
	for _, pkg := range []*sdk.Dependency{root, dep} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddEdge(root.ID, dep.ID); err != nil {
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
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithRegistry(registry).WithEnrichEnabled(true)
	model.SelectView(6) // Posture is the 6th tab (1-indexed: Overview, Components, Vulns, Licenses, Findings, Posture, Source)

	plain := render.StripANSI(model.View(160, 40))
	for _, want := range []string{
		"Posture",
		"Checks (2)",
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
	root := sdk.NewDependencyRef("demo-app", "1.0.0")
	if err := g.AddNode(root); err != nil {
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

func TestPostureTab_CheckNotesFitSplitPane(t *testing.T) {
	g := sdk.New()
	registry := sdk.NewPackageRegistry()
	const purl = "pkg:golang/github.com/anchore/go-struct-converter@1.0.0"
	dep := sdk.NewDependency(sdk.Dependency{Name: "go-struct-converter", Version: "1.0.0", PURL: purl})
	regPkg := registry.Ensure(purl)
	regPkg.Name = "go-struct-converter"
	regPkg.Version = "1.0.0"
	regPkg.Scorecard = newTestScorecardTUI("github.com/anchore/go-struct-converter", 2.0,
		sdk.PackageScorecardCheck{Name: "CI-Best-Practices", Score: 0, Reason: "agg note should stay visible"},
	)
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add package: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:    ".",
			PrimaryDetector: "go-detector",
			Ecosystem:       sdk.EcosystemGo,
		},
		DetectorName: "go-detector",
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "go.mod"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithRegistry(registry).WithEnrichEnabled(true)
	model.SelectView(6)

	plain := render.StripANSI(model.View(140, 34))
	if !strings.Contains(plain, "agg 2.0/10") {
		t.Fatalf("expected posture check notes to fit the split pane; got:\n%s", plain)
	}
	if strings.Contains(plain, "agg 2...") {
		t.Fatalf("posture check notes were truncated:\n%s", plain)
	}
}

func TestTopAffectedLines_FitBoxBudget(t *testing.T) {
	pkg := sdk.NewDependency(sdk.Dependency{
		Name:    "org.springframework:spring-web",
		Version: "6.0.0",
		Scopes:  sdk.ScopesOf(sdk.ScopeRuntime),
	})
	rows := make([]packageVulnerabilityRow, 0, 12)
	for i := 0; i < 12; i++ {
		rows = append(rows, packageVulnerabilityRow{
			pkg:           pkg,
			vulnerability: sdk.Vulnerability{ID: "CVE-2026-" + string(rune('A'+i))},
		})
	}

	for _, width := range []int{58, 90, 132, 140} {
		lines := topAffectedLines(rows, 5, width)
		if len(lines) != 1 {
			t.Fatalf("topAffectedLines(width=%d) produced %d lines, want 1", width, len(lines))
		}
		plain := render.StripANSI(lines[0])
		if visible := len([]rune(plain)); visible > width-2 {
			t.Errorf("top affected line at width=%d has %d visible cols, want <= %d.\nLine: %q", width, visible, width-2, plain)
		}
		if !strings.HasSuffix(plain, " 12") {
			t.Errorf("top affected line at width=%d lost count suffix:\n%s", width, plain)
		}
	}
}

func TestPostureRowsFromGraph_DedupesAndSortsWorstFirst(t *testing.T) {
	g := sdk.New()
	registry := sdk.NewPackageRegistry()
	add := func(name, purl, repo string, score float64) *sdk.Dependency {
		dep := sdk.NewDependencyWithID(purl, sdk.Dependency{Name: name, Version: "1", PURL: purl})
		regPkg := registry.Ensure(purl)
		regPkg.Name = name
		regPkg.Version = "1"
		regPkg.Scorecard = newTestScorecardTUI(repo, score)
		return dep
	}
	low := add("low", "pkg:npm/low@1", "github.com/low/repo", 2.0)
	high := add("high", "pkg:npm/high@1", "github.com/high/repo", 9.0)
	mid := add("mid", "pkg:npm/mid@1", "github.com/mid/repo", 6.0)
	monoA := add("a", "pkg:npm/a@1", "github.com/mono/repo", 7.5)
	monoB := add("b", "pkg:npm/b@1", "github.com/mono/repo", 7.5)
	for _, pkg := range []*sdk.Dependency{low, high, mid, monoA, monoB} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	rows := postureRowsFromGraph(g, registry)
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

func TestPostureTopFailingLines_FitBoxBudget(t *testing.T) {
	rows := make([]postureRow, 0, 196)
	for i := 0; i < 196; i++ {
		rows = append(rows, postureRow{
			repository: "github.com/example/repo",
			card: newTestScorecardTUI("github.com/example/repo", 4.8,
				sdk.PackageScorecardCheck{Name: "CI-Best-Practices", Score: 1},
				sdk.PackageScorecardCheck{Name: "Security-Policy", Score: 2},
			),
		})
	}

	for _, width := range []int{58, 90, 132, 140} {
		lines := postureTopFailingLines(rows, width)
		if len(lines) == 0 {
			t.Fatalf("postureTopFailingLines(width=%d) produced no lines", width)
		}
		for _, line := range lines {
			plain := render.StripANSI(line)
			if visible := len([]rune(plain)); visible > width-2 {
				t.Errorf("posture failing line at width=%d has %d visible cols, want <= %d.\nLine: %q", width, visible, width-2, plain)
			}
			if !strings.HasSuffix(plain, " 196/196") {
				t.Errorf("posture failing line at width=%d lost failure suffix:\n%s", width, plain)
			}
		}
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
					Before: output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 5.0,
						sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 4},
					)},
					After: output.PackageRef{Name: "shared", Scorecard: newTestScorecardTUI("github.com/shared/repo", 8.0,
						sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 7},
					)},
				}},
				Added: []output.DiffPackageChange{{
					Package: output.PackageRef{Name: "new", Scorecard: newTestScorecardTUI("github.com/new/repo", 6.0,
						sdk.PackageScorecardCheck{Name: "Code-Review", Score: 6},
					)},
				}},
			},
		},
	}
	model := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	model.SelectView(6)

	plain := render.StripANSI(model.View(160, 40))
	for _, want := range []string{
		"Posture",
		"Checks (2)",
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
