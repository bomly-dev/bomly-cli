package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
	tea "github.com/charmbracelet/bubbletea"
)

func TestInteractiveManifestRows_OnlyIncludesManifests(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	direct := sdk.NewPackageRef("react", "18.2.0")
	transitive := sdk.NewPackageRef("loose-envify", "1.4.0")
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := g.AddPackage(direct); err != nil {
		t.Fatalf("add direct: %v", err)
	}
	if err := g.AddPackage(transitive); err != nil {
		t.Fatalf("add transitive: %v", err)
	}
	if err := g.AddDependency(root.ID, direct.ID); err != nil {
		t.Fatalf("add root->direct: %v", err)
	}
	if err := g.AddDependency(direct.ID, transitive.ID); err != nil {
		t.Fatalf("add direct->transitive: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	rows := manifestRows(consolidated)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].id != "package-lock.json" {
		t.Fatalf("expected manifest row %q, got %#v", "package-lock.json", rows)
	}
	if rows[0].relationship != "manifest" {
		t.Fatalf("expected manifest relationship, got %q", rows[0].relationship)
	}
}

func TestInteractiveListModel_ViewIncludesDetails(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	dep := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := g.AddPackage(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(2)
	model.Move(3)
	view := model.View(90, 26)

	plain := render.StripANSI(view)
	for _, want := range []string{
		"Components (2)",
		"Manifest: package-lock.json",
		"Component Details",
		"Component",
		"react@18.2.0",
		"Scope: runtime",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, plain)
		}
	}

	// Verify both root and direct relationships are shown
	if !strings.Contains(plain, "Relationship: root") && !strings.Contains(plain, "Relationship: direct") {
		t.Fatalf("expected view to contain both 'Relationship: root' or 'Relationship: direct', got:\n%s", plain)
	}
	if !strings.Contains(view, "\x1b[") {
		t.Fatalf("expected ANSI styling in view, got:\n%s", view)
	}
}

func TestNewDiffInteractiveModel_ViewIncludesManifestChanges(t *testing.T) {
	model := NewDiff(output.DiffResponse{
		Comparison: output.DiffComparison{Base: "base", Head: "head"},
		Results: output.DiffResults{Manifests: []output.DiffManifestResult{
			{
				Status:         "changed",
				Path:           "package.json",
				PackageManager: "npm",
				Added: []output.DiffPackageChange{
					{Package: output.PackageRef{Name: "zod", Version: "3.23.0"}},
				},
				Changed: []output.DiffChangedPackage{
					{Before: output.PackageRef{Name: "react", Version: "18.2.0"}, After: output.PackageRef{Name: "react", Version: "19.0.0"}},
				},
			},
		}},
		Summary: output.DiffSummary{
			ChangedManifestCount: 1,
			AddedPackageCount:    1,
			ChangedPackageCount:  1,
		},
	}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})

	view := model.View(140, 32)
	for _, want := range []string{
		"DIFF",
		"base -> head",
		"[1] Overview",
		"[2] Components",
		"Manifests",
		"Packages",
	} {
		if !strings.Contains(render.StripANSI(view), want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "\x1b[") {
		t.Fatalf("expected ANSI styling in view, got:\n%s", view)
	}
}

func TestNewScanInteractiveModel_ViewIncludesGraphSummary(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	dep := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := g.AddPackage(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{
		Name:      "demo-app",
		Path:      "/tmp/demo-app",
		Ecosystem: "npm",
	}, consolidated, graphValue, nil)
	model.SelectView(2)
	view := model.View(100, 20)
	plain := render.StripANSI(view)

	for _, want := range []string{
		"Components (2)",
		"Component Details",
		"Group: Dependency",
		"demo-app (1 manifests)",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestInteractivePackageDisplayName_IncludesScope(t *testing.T) {
	pkg := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if got := packageDisplayName(pkg); got != "react@18.2.0 [runtime]" {
		t.Fatalf("expected scoped display name, got %q", got)
	}
}

func TestScanInteractiveModel_MultiManifestNavigation(t *testing.T) {
	g := sdk.New()
	r1 := sdk.NewPackageRef("web-app", "1.0.0")
	r2 := sdk.NewPackageRef("api", "2.0.0")
	c1 := sdk.NewPackageRef("react", "18.2.0")
	c2 := sdk.NewPackageRef("zod", "3.23.0")
	for _, pkg := range []*sdk.Package{r1, r2, c1, c2} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(r1.ID, c1.ID); err != nil {
		t.Fatalf("add dependency r1: %v", err)
	}
	if err := g.AddDependency(r2.ID, c2.ID); err != nil {
		t.Fatalf("add dependency r2: %v", err)
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/multi"},
				RelativePath:            ".",
				PrimaryDetector:         "maven-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven},
				Ecosystem:               sdk.EcosystemMaven,
			},
			DetectorName: "maven-detector",
			Origin:       sdk.CoreOrigin,
			Graphs:       engine.SingleGraphContainer(graphFixtureForInteractive(t, r1, c1), sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}),
		},
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/multi"},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			Origin:       sdk.CoreOrigin,
			Graphs:       engine.SingleGraphContainer(graphFixtureForInteractive(t, r2, c2), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "multi", Path: "/tmp/multi"}, consolidated, graphValue, nil)
	plain := render.StripANSI(model.View(100, 30))
	if !strings.Contains(plain, "[1] Overview") || !strings.Contains(plain, "Manifests: 2") {
		t.Fatalf("expected overview view, got:\n%s", plain)
	}

	wrapper := &teaModel{inner: model, width: 100, height: 20}
	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	wrapper = updated.(*teaModel)
	plain = render.StripANSI(wrapper.View())
	if !strings.Contains(plain, "multi (2 manifests)") || !strings.Contains(plain, "zod@3.23.0") {
		t.Fatalf("expected unified component tree, got:\n%s", plain)
	}

	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	wrapper = updated.(*teaModel)
	plain = render.StripANSI(wrapper.View())
	if !strings.Contains(plain, "Components (4)") {
		t.Fatalf("expected backspace to keep unified component tree, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_SingleManifestAutoEntry_NoBackNavigation(t *testing.T) {
	g := sdk.New()
	r1 := sdk.NewPackageRef("web-app", "1.0.0")
	c1 := sdk.NewPackageRef("react", "18.2.0")
	for _, pkg := range []*sdk.Package{r1, c1} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(r1.ID, c1.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/single"},
			RelativePath:            ".",
			PrimaryDetector:         "maven-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerMaven},
			Ecosystem:               sdk.EcosystemMaven,
		},
		DetectorName: "maven-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(graphFixtureForInteractive(t, r1, c1), sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "single", Path: "/tmp/single"}, consolidated, graphValue, nil)
	if model.CanGoBack() {
		t.Fatal("expected single-manifest mode to disable back navigation")
	}

	wrapper := &teaModel{inner: model, width: 100, height: 20}
	before := render.StripANSI(wrapper.View())
	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	wrapper = updated.(*teaModel)
	after := render.StripANSI(wrapper.View())
	if before != after {
		t.Fatalf("expected back key to have no effect in single-manifest mode")
	}
}

func graphFixtureForInteractive(t *testing.T, root, dep *sdk.Package) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, pkg := range []*sdk.Package{root, dep} {
		if err := g.AddPackage(pkg.Clone()); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return g
}

func consolidatedForInteractive(t *testing.T, results []sdk.DetectionResult) sdk.ConsolidatedGraph {
	t.Helper()
	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	return consolidated
}

func TestInteractiveTeaModel_KeyBindings(t *testing.T) {
	inner := &listModel{
		items: []listItem{{title: "one"}, {title: "two"}, {title: "three"}},
	}
	model := &teaModel{inner: inner, width: 80, height: 20}

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(*teaModel)
	if cmd != nil {
		t.Fatalf("expected no command for down key, got %#v", cmd)
	}
	if inner.selected != 1 {
		t.Fatalf("expected selection to move down to 1, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	model = updated.(*teaModel)
	if inner.selected != 0 {
		t.Fatalf("expected selection to move back up to 0, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(*teaModel)
	if inner.selected != 2 {
		t.Fatalf("expected selection to move to end, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyHome})
	model = updated.(*teaModel)
	if inner.selected != 0 {
		t.Fatalf("expected home key to move to top, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(*teaModel)
	if inner.selected != 2 {
		t.Fatalf("expected end key to move to bottom, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*teaModel)
	if !model.confirmQuit {
		t.Fatal("expected escape key to request quit confirmation")
	}
}

func TestInteractiveTeaModel_QuitConfirmationCancelsAndConfirms(t *testing.T) {
	model := &teaModel{inner: &listModel{}, width: 80, height: 20}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*teaModel)
	if !model.confirmQuit {
		t.Fatal("expected q to open quit confirmation")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*teaModel)
	if model.quitting || model.confirmQuit {
		t.Fatal("expected esc to cancel quit confirmation")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*teaModel)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(*teaModel)
	if !model.quitting {
		t.Fatal("expected enter to confirm quit")
	}
}

func TestInteractiveTeaModel_QuitConfirmationOverlaysAndClears(t *testing.T) {
	inner := &listModel{
		title:          "Demo",
		summary:        []string{"Packages  2"},
		navigationHelp: "help",
		items: []listItem{
			{title: "alpha"},
			{title: "beta"},
		},
	}
	model := &teaModel{inner: inner, width: 80, height: 16}

	before := render.StripANSI(model.View())
	if !strings.Contains(before, " Demo ") {
		t.Fatalf("expected header to be visible before quit confirmation, got:\n%s", before)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*teaModel)
	during := render.StripANSI(model.View())
	if !strings.Contains(during, " Demo ") {
		t.Fatalf("expected header to remain visible during quit confirmation, got:\n%s", during)
	}
	if !strings.Contains(during, "Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels.") {
		t.Fatalf("expected quit confirmation message, got:\n%s", during)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*teaModel)
	after := render.StripANSI(model.View())
	if strings.Contains(after, "Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels.") {
		t.Fatalf("expected quit confirmation message to clear after cancel, got:\n%s", after)
	}
	if !strings.Contains(after, " Demo ") {
		t.Fatalf("expected header to remain visible after cancel, got:\n%s", after)
	}
}

func TestInteractiveTeaModel_SearchJump(t *testing.T) {
	inner := &listModel{
		items: []listItem{
			{title: "alpha"},
			{title: "react@18.2.0"},
			{title: "zod@3.23.0"},
		},
	}
	model := &teaModel{inner: inner, width: 80, height: 20}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	model = updated.(*teaModel)
	if !inner.IsSearching() {
		t.Fatal("expected search mode to start")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r', 'e', 'a'}})
	model = updated.(*teaModel)
	if inner.selected != 1 {
		t.Fatalf("expected search to jump to index 1, got %d", inner.selected)
	}
	if inner.searchQuery != "rea" {
		t.Fatalf("expected search query to be rea, got %q", inner.searchQuery)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_ = updated.(*teaModel)
	if inner.IsSearching() {
		t.Fatal("expected enter to finish search mode")
	}
}

func TestInteractiveListModel_ViewIncludesSearchPrompt(t *testing.T) {
	model := &listModel{
		title:          "Search Demo",
		summary:        []string{"Packages  3"},
		navigationHelp: "help",
		items:          []listItem{{title: "alpha"}, {title: "react@18.2.0"}, {title: "zod@3.23.0"}},
		searching:      true,
		searchQuery:    "react",
		searchMatch:    true,
	}

	view := render.StripANSI(model.View(90, 18))
	for _, want := range []string{
		"Search /react",
		"Enter: keep",
		"Esc: clear",
		"react@18.2.0",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestInteractiveListModel_DetailPaneScrolls(t *testing.T) {
	items := []listItem{{
		title: "alpha",
		details: []string{
			"detail-01",
			"detail-02",
			"detail-03",
			"detail-04",
			"detail-05",
			"detail-06",
			"detail-07",
			"detail-08",
			"detail-09",
			"detail-10",
			"detail-11",
			"detail-12",
		},
	}}
	model := &listModel{
		title:          "Scroll Demo",
		navigationHelp: "help",
		items:          items,
	}

	before := render.StripANSI(model.View(80, 12))
	if !strings.Contains(before, "detail-01") {
		t.Fatalf("expected initial details to include first line, got:\n%s", before)
	}
	if strings.Contains(before, "detail-09") {
		t.Fatalf("expected initial details to be clipped before detail-09, got:\n%s", before)
	}

	model.ScrollDetails(4)
	after := render.StripANSI(model.View(80, 12))
	if strings.Contains(after, "detail-01") {
		t.Fatalf("expected scrolled details to move past detail-01, got:\n%s", after)
	}
	if !strings.Contains(after, "detail-09") {
		t.Fatalf("expected scrolled details to include detail-09, got:\n%s", after)
	}
}

func TestInteractiveTeaModel_PageDownScrollsDetailPane(t *testing.T) {
	inner := &listModel{
		title:          "Scroll Demo",
		navigationHelp: "help",
		items: []listItem{{
			title: "alpha",
			details: []string{
				"detail-01",
				"detail-02",
				"detail-03",
				"detail-04",
				"detail-05",
				"detail-06",
				"detail-07",
				"detail-08",
				"detail-09",
				"detail-10",
				"detail-11",
				"detail-12",
			},
		}},
	}
	model := &teaModel{inner: inner, width: 80, height: 12}

	before := render.StripANSI(model.View())
	if !strings.Contains(before, "detail-01") {
		t.Fatalf("expected initial details to include first line, got:\n%s", before)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(*teaModel)
	after := render.StripANSI(model.View())
	if strings.Contains(after, "detail-01") {
		t.Fatalf("expected page-down to scroll details, got:\n%s", after)
	}
	if !strings.Contains(after, "detail-09") {
		t.Fatalf("expected page-down to reveal later detail lines, got:\n%s", after)
	}
}

func TestInteractiveListModel_HelpWrapsAcrossMultipleLines(t *testing.T) {
	model := &listModel{
		title:          "Help Wrap Demo",
		navigationHelp: "Use page up and page down to scroll expanded details. Use q to quit interactive mode.",
		filterHelp:     "Use slash to search and filter.",
		items:          []listItem{{title: "alpha", details: []string{"detail"}}},
	}

	view := render.StripANSI(model.View(60, 14))
	for _, fragment := range []string{"Navigation:", "Filter/Search:"} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected help label %q in view, got:\n%s", fragment, view)
		}
	}
	for _, fragment := range []string{
		"Use slash to search",
		"page up and page down",
		"scroll expanded",
		"details. Use q to quit interactive mode.",
		"Use q to quit interactive mode.",
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected wrapped help fragment %q in view, got:\n%s", fragment, view)
		}
	}
	if strings.Contains(view, "...") {
		t.Fatalf("expected wrapped help text without truncation ellipsis, got:\n%s", view)
	}
}

func TestScanInteractiveModel_FiltersAndScopeBadges(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	runtimeDep := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	devDep := sdk.NewPackage(sdk.Package{Name: "vitest", Version: "2.0.0", Scope: "development"})
	for _, pkg := range []*sdk.Package{root, runtimeDep, devDep} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(root.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add dependency runtime: %v", err)
	}
	if err := g.AddDependency(root.ID, devDep.ID); err != nil {
		t.Fatalf("add dependency development: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(2)

	plain := render.StripANSI(model.View(100, 30))
	if !strings.Contains(plain, "react@18.2.0") || !strings.Contains(plain, "vitest@2.0.0") {
		t.Fatalf("expected scoped component rows, got:\n%s", plain)
	}

	model.CycleScopeFilter()
	plain = render.StripANSI(model.View(100, 30))
	if !strings.Contains(plain, "react@18.2.0") || strings.Contains(plain, "vitest@2.0.0") {
		t.Fatalf("expected runtime scope filter to keep only runtime packages, got:\n%s", plain)
	}
	if !strings.Contains(plain, "Components (1)") || !strings.Contains(plain, "Components: 1 of 3") || !strings.Contains(plain, "package-lock.json") {
		t.Fatalf("expected component counts to reflect runtime scope filter while keeping manifest visible, got:\n%s", plain)
	}

	model.CycleRelationshipFilter()
	model.CycleRelationshipFilter()
	plain = render.StripANSI(model.View(100, 30))
	if strings.Contains(plain, "demo-app@1.0.0  ROOT") || !strings.Contains(plain, "react@18.2.0") {
		t.Fatalf("expected direct relationship filter to hide root row, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_EcosystemFilterUpdatesComponents(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	npmDep := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Ecosystem: "npm"})
	goDep := sdk.NewPackage(sdk.Package{Name: "cobra", Version: "1.8.0", Ecosystem: "go"})
	for _, pkg := range []*sdk.Package{root, npmDep, goDep} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	for _, dep := range []*sdk.Package{npmDep, goDep} {
		if err := g.AddDependency(root.ID, dep.ID); err != nil {
			t.Fatalf("add dependency: %v", err)
		}
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.LockfileTechnique,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(2)
	model.ecosystemFilter = "npm"
	model.rebuildListPreserveSelection()

	plain := render.StripANSI(model.View(110, 32))
	if !strings.Contains(plain, "Ecosystem: npm") || !strings.Contains(plain, "Components (2)") {
		t.Fatalf("expected npm ecosystem filter state and count, got:\n%s", plain)
	}
	if !strings.Contains(plain, "react@18.2.0") || strings.Contains(plain, "cobra@1.8.0") {
		t.Fatalf("expected ecosystem filter to keep npm rows only, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_ManifestDetailsIncludeDetectorMetadata(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add package: %v", err)
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			PlannedDetectors:        []string{"npm-detector", "syft-detector"},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.LockfileTechnique,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(2)
	model.Move(1)

	plain := render.StripANSI(model.View(110, 32))
	for _, want := range []string{"Detector", "Name: npm-detector", "Package managers: npm", "Planned chain: npm-detector, syft-detector"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected manifest details to contain %q, got:\n%s", want, plain)
		}
	}
}

func TestScanInteractiveModel_FindingsCanGroupByEcosystem(t *testing.T) {
	pkg := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Ecosystem: "npm"})
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, sdk.ConsolidatedGraph{}, sdk.New(), []sdk.Finding{
		{ID: "F-1", Kind: sdk.FindingKindLicense, Severity: "high", Package: pkg},
	})
	model.SelectView(5)
	for range 3 {
		model.CycleGroup()
	}

	plain := render.StripANSI(model.View(100, 26))
	if !strings.Contains(plain, "Group: ecosystem") || !strings.Contains(plain, "npm (1)") {
		t.Fatalf("expected findings grouped by ecosystem, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_UsesEnrichedVulnerabilitiesWithoutFindings(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	dep := sdk.NewPackage(sdk.Package{
		Name:      "react",
		Version:   "18.2.0",
		Ecosystem: "npm",
		Vulnerabilities: []sdk.PackageVulnerability{{
			ID:       "CVE-2026-0001",
			Source:   "osv",
			Title:    "demo issue",
			Severity: "high",
		}},
	})
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
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	overview := render.StripANSI(model.View(120, 32))
	if !strings.Contains(overview, "Components: 2 | Vulns: 1 | Licenses: 0 | Findings: 0") {
		t.Fatalf("expected overview to count enriched vulnerabilities without findings, got:\n%s", overview)
	}
	if !strings.Contains(overview, "1 High") {
		t.Fatalf("expected overview severity cards to use enriched vulnerabilities, got:\n%s", overview)
	}

	model.SelectView(2)
	model.Move(3)
	components := render.StripANSI(model.View(110, 32))
	if !strings.Contains(components, "react@18.2.0") || !strings.Contains(components, "HIGH") {
		t.Fatalf("expected components tab to expose vulnerability severity from enrichment, got:\n%s", components)
	}
	if !strings.Contains(components, "Vulnerabilities (1)") {
		t.Fatalf("expected component details to use enriched vulnerabilities, got:\n%s", components)
	}

	model.SelectView(3)
	vulnerabilities := render.StripANSI(model.View(110, 32))
	if !strings.Contains(vulnerabilities, "Vulnerabilities (1)") || !strings.Contains(vulnerabilities, "CVE-2026-0001") {
		t.Fatalf("expected vulnerabilities tab to use enriched package vulnerabilities, got:\n%s", vulnerabilities)
	}
	if strings.Contains(vulnerabilities, "No enriched vulnerabilities found") {
		t.Fatalf("expected vulnerabilities tab to render available enrichment, got:\n%s", vulnerabilities)
	}

	model.SelectView(5)
	findings := render.StripANSI(model.View(110, 32))
	if !strings.Contains(findings, "No findings found. Run with --audit") || !strings.Contains(findings, "Findings: 0") {
		t.Fatalf("expected findings tab to remain audit-backed, got:\n%s", findings)
	}
}

func TestScanInteractiveModel_VulnerabilityFilterKeepsGlobalSummaries(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	react := sdk.NewPackage(sdk.Package{
		Name:      "react",
		Version:   "18.2.0",
		Ecosystem: "npm",
		Vulnerabilities: []sdk.PackageVulnerability{{
			ID:       "CVE-HIGH",
			Severity: "high",
		}},
	})
	lodash := sdk.NewPackage(sdk.Package{
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: "npm",
		Vulnerabilities: []sdk.PackageVulnerability{{
			ID:       "CVE-LOW",
			Severity: "low",
		}},
	})
	for _, pkg := range []*sdk.Package{root, react, lodash} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	for _, dep := range []*sdk.Package{react, lodash} {
		if err := g.AddDependency(root.ID, dep.ID); err != nil {
			t.Fatalf("add dependency: %v", err)
		}
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil).WithEnrichEnabled(true)
	model.SelectView(3)
	model.severityFilter = "high"
	model.rebuildListPreserveSelection()

	plain := render.StripANSI(model.View(120, 32))
	for _, want := range []string{
		"Vulnerabilities (1)",
		"CVE-HIGH",
		"1 High",
		"1 Low",
		"Affected components: 2",
		"react@18.2.0",
		"lodash@4.17.20",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected filtered vulnerability view to contain %q, got:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "CVE-LOW") {
		t.Fatalf("expected severity filter to hide low vulnerability rows, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_VulnerabilityFilterEmptyStateDistinguishesNoMatchesFromNoEnrich(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	dep := sdk.NewPackage(sdk.Package{
		Name:      "react",
		Version:   "18.2.0",
		Ecosystem: "npm",
		Vulnerabilities: []sdk.PackageVulnerability{{
			ID:       "CVE-HIGH",
			Severity: "high",
		}},
	})
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
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil).WithEnrichEnabled(true)
	model.SelectView(3)
	model.severityFilter = "low"
	model.rebuildListPreserveSelection()
	filtered := render.StripANSI(model.View(110, 32))
	if !strings.Contains(filtered, "No vulnerabilities match the selected filters.") {
		t.Fatalf("expected filtered empty state, got:\n%s", filtered)
	}
	if strings.Contains(filtered, "Run with --enrich") {
		t.Fatalf("expected filtered empty state not to blame missing enrichment, got:\n%s", filtered)
	}

	noEnrich := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, sdk.ConsolidatedGraph{}, sdk.New(), nil)
	noEnrich.SelectView(3)
	plain := render.StripANSI(noEnrich.View(110, 32))
	if !strings.Contains(plain, "No enriched vulnerabilities found. Run with --enrich to populate vulnerability data.") {
		t.Fatalf("expected no-enrich empty state, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_ReachabilityFilterCyclesFromKeyboard(t *testing.T) {
	model := newScanReachabilityFilterModel(t, true)
	model.SelectView(2)
	wrapper := &teaModel{inner: model, width: 180, height: 40}

	components := render.StripANSI(model.View(180, 40))
	if !strings.Contains(components, "a reachability") || !strings.Contains(components, "Reachability: All") {
		t.Fatalf("expected enabled components view to expose reachability controls, got:\n%s", components)
	}

	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	wrapper = updated.(*teaModel)
	if model.reachabilityFilter != string(sdk.ReachabilityReachable) {
		t.Fatalf("expected first a key to select reachable filter, got %q", model.reachabilityFilter)
	}
	assertInteractiveListTitles(t, model, []string{"reachable-lib@1.0.0", "mixed-lib@1.0.0"}, []string{"unreachable-lib@1.0.0", "unknown-lib@1.0.0", "nil-lib@1.0.0"})
	if plain := render.StripANSI(wrapper.View()); !strings.Contains(plain, "Reachability: Reachable") {
		t.Fatalf("expected reachable state line, got:\n%s", plain)
	}

	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	wrapper = updated.(*teaModel)
	if model.reachabilityFilter != string(sdk.ReachabilityUnreachable) {
		t.Fatalf("expected second a key to select unreachable filter, got %q", model.reachabilityFilter)
	}
	assertInteractiveListTitles(t, model, []string{"unreachable-lib@1.0.0"}, []string{"reachable-lib@1.0.0", "mixed-lib@1.0.0", "unknown-lib@1.0.0", "nil-lib@1.0.0"})

	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	wrapper = updated.(*teaModel)
	if model.reachabilityFilter != "" {
		t.Fatalf("expected third a key to restore all filter, got %q", model.reachabilityFilter)
	}

	model.SelectView(3)
	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	wrapper = updated.(*teaModel)
	assertInteractiveListTitles(t, model, []string{"CVE-REACHABLE", "CVE-MIXED-REACHABLE"}, []string{"CVE-UNREACHABLE", "CVE-MIXED-UNREACHABLE", "CVE-UNKNOWN", "CVE-NIL"})
	if plain := render.StripANSI(wrapper.View()); !strings.Contains(plain, "Reachability: Reachable") {
		t.Fatalf("expected vulnerability state line to show reachable filter, got:\n%s", plain)
	}

	_, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	assertInteractiveListTitles(t, model, []string{"CVE-UNREACHABLE", "CVE-MIXED-UNREACHABLE"}, []string{"CVE-REACHABLE", "CVE-MIXED-REACHABLE", "CVE-UNKNOWN", "CVE-NIL"})
}

func TestScanInteractiveModel_ReachabilityFilterUnavailableIsHiddenAndNoOp(t *testing.T) {
	model := newScanReachabilityFilterModel(t, false)
	model.SelectView(2)
	wrapper := &teaModel{inner: model, width: 180, height: 40}
	plain := render.StripANSI(wrapper.View())
	if strings.Contains(plain, "a reachability") || strings.Contains(plain, "Reachability:") {
		t.Fatalf("expected disabled reachability filter to stay hidden, got:\n%s", plain)
	}
	if _, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}); model.reachabilityFilter != "" {
		t.Fatalf("expected a key to be ignored while reachability is disabled, got %q", model.reachabilityFilter)
	}

	noData := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, sdk.ConsolidatedGraph{}, sdk.New(), nil).WithReachabilityEnabled(true)
	noData.SelectView(3)
	plain = render.StripANSI(noData.View(180, 40))
	if strings.Contains(plain, "a reachability") || strings.Contains(plain, "Reachability:") {
		t.Fatalf("expected filter to stay hidden without reachability annotations, got:\n%s", plain)
	}
	noData.CycleReachabilityFilter()
	if noData.reachabilityFilter != "" {
		t.Fatalf("expected cycle to be ignored without annotations, got %q", noData.reachabilityFilter)
	}

	model = newScanReachabilityFilterModel(t, true)
	model.SelectView(1)
	model.CycleReachabilityFilter()
	if model.reachabilityFilter != "" {
		t.Fatalf("expected cycle to be ignored outside components and vulnerabilities, got %q", model.reachabilityFilter)
	}
}

func TestScanInteractiveModel_OverviewShowsReachableSeverityCountsWhenEnabled(t *testing.T) {
	enabled := newScanReachabilityFilterModel(t, true)
	plain := render.StripANSI(enabled.View(240, 48))
	if !strings.Contains(plain, "6 High (2 reachable)") {
		t.Fatalf("expected overview vulnerability severity count to include reachable count, got:\n%s", plain)
	}

	disabled := newScanReachabilityFilterModel(t, false)
	plain = render.StripANSI(disabled.View(240, 48))
	if strings.Contains(plain, "reachable)") {
		t.Fatalf("expected overview reachable counts to stay hidden when disabled, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_VulnerabilityRowsShowReachabilityBadgesWhenEnabled(t *testing.T) {
	model := newScanReachabilityFilterModel(t, true)
	model.SelectView(3)
	assertInteractiveItemBadges(t, model, "CVE-REACHABLE", []string{"reachable"})
	assertInteractiveItemBadges(t, model, "CVE-UNREACHABLE", []string{"unreachable"})
	assertInteractiveItemBadges(t, model, "CVE-UNKNOWN", nil)
	assertInteractiveItemBadges(t, model, "CVE-NIL", nil)

	disabled := newScanReachabilityFilterModel(t, false)
	disabled.SelectView(3)
	assertInteractiveItemBadges(t, disabled, "CVE-REACHABLE", nil)
}

func TestScanInteractiveModel_SeverityFilterIncludesAnyAndNone(t *testing.T) {
	if got := nextSeverityFilter(""); got != "any" {
		t.Fatalf("nextSeverityFilter(all) = %q, want any", got)
	}
	if got := nextSeverityFilter("any"); got != "none" {
		t.Fatalf("nextSeverityFilter(any) = %q, want none", got)
	}

	model := newScanReachabilityFilterModel(t, true)
	model.SelectView(2)
	model.CycleSeverityFilter()
	if model.severityFilter != "any" {
		t.Fatalf("expected first severity cycle to select any, got %q", model.severityFilter)
	}
	assertInteractiveListTitles(t, model, []string{"reachable-lib@1.0.0", "unreachable-lib@1.0.0", "mixed-lib@1.0.0", "unknown-lib@1.0.0", "nil-lib@1.0.0"}, []string{"demo-app@1.0.0"})

	model.CycleSeverityFilter()
	if model.severityFilter != "none" {
		t.Fatalf("expected second severity cycle to select none, got %q", model.severityFilter)
	}
	assertInteractiveListTitles(t, model, []string{"demo-app@1.0.0"}, []string{"reachable-lib@1.0.0", "unreachable-lib@1.0.0", "mixed-lib@1.0.0", "unknown-lib@1.0.0", "nil-lib@1.0.0"})

	model.SelectView(3)
	model.severityFilter = "any"
	model.rebuildListPreserveSelection()
	assertInteractiveListTitles(t, model, []string{"CVE-REACHABLE", "CVE-UNREACHABLE", "CVE-MIXED-REACHABLE", "CVE-MIXED-UNREACHABLE", "CVE-UNKNOWN", "CVE-NIL"}, nil)
	model.severityFilter = "none"
	model.rebuildListPreserveSelection()
	if len(model.List().items) != 0 {
		t.Fatalf("expected none severity filter to hide every vulnerability row, got %#v", model.List().items)
	}
}

func newScanReachabilityFilterModel(t *testing.T, enabled bool) *scanModel {
	t.Helper()
	vulnerability := func(id string, reachability *sdk.Reachability) sdk.PackageVulnerability {
		return sdk.PackageVulnerability{ID: id, Severity: "high", Reachability: reachability}
	}
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	reachable := sdk.NewPackage(sdk.Package{
		Name:            "reachable-lib",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		Vulnerabilities: []sdk.PackageVulnerability{vulnerability("CVE-REACHABLE", &sdk.Reachability{Status: sdk.ReachabilityReachable})},
	})
	unreachable := sdk.NewPackage(sdk.Package{
		Name:            "unreachable-lib",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		Vulnerabilities: []sdk.PackageVulnerability{vulnerability("CVE-UNREACHABLE", &sdk.Reachability{Status: sdk.ReachabilityUnreachable})},
	})
	mixed := sdk.NewPackage(sdk.Package{
		Name:      "mixed-lib",
		Version:   "1.0.0",
		Ecosystem: "npm",
		Vulnerabilities: []sdk.PackageVulnerability{
			vulnerability("CVE-MIXED-REACHABLE", &sdk.Reachability{Status: sdk.ReachabilityReachable}),
			vulnerability("CVE-MIXED-UNREACHABLE", &sdk.Reachability{Status: sdk.ReachabilityUnreachable}),
		},
	})
	unknown := sdk.NewPackage(sdk.Package{
		Name:            "unknown-lib",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		Vulnerabilities: []sdk.PackageVulnerability{vulnerability("CVE-UNKNOWN", &sdk.Reachability{Status: sdk.ReachabilityUnknown})},
	})
	nilReachability := sdk.NewPackage(sdk.Package{
		Name:            "nil-lib",
		Version:         "1.0.0",
		Ecosystem:       "npm",
		Vulnerabilities: []sdk.PackageVulnerability{vulnerability("CVE-NIL", nil)},
	})
	g := sdk.New()
	for _, pkg := range []*sdk.Package{root, reachable, unreachable, mixed, unknown, nilReachability} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	for _, pkg := range []*sdk.Package{reachable, unreachable, mixed, unknown, nilReachability} {
		if err := g.AddDependency(root.ID, pkg.ID); err != nil {
			t.Fatalf("add dependency: %v", err)
		}
	}
	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	return NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil).WithEnrichEnabled(true).WithReachabilityEnabled(enabled)
}

func assertInteractiveListTitles(t *testing.T, model *scanModel, contains, excludes []string) {
	t.Helper()
	titles := make([]string, 0, len(model.List().items))
	titleSet := make(map[string]struct{}, len(model.List().items))
	for _, item := range model.List().items {
		titles = append(titles, item.title)
		titleSet[item.title] = struct{}{}
	}
	joined := strings.Join(titles, "\n")
	for _, want := range contains {
		if _, ok := titleSet[want]; !ok {
			t.Fatalf("expected interactive list titles to contain %q, got:\n%s", want, joined)
		}
	}
	for _, excluded := range excludes {
		if _, ok := titleSet[excluded]; ok {
			t.Fatalf("expected interactive list titles to exclude %q, got:\n%s", excluded, joined)
		}
	}
}

func assertInteractiveItemBadges(t *testing.T, model *scanModel, title string, expectedReachability []string) {
	t.Helper()
	for _, item := range model.List().items {
		if item.title != title {
			continue
		}
		var actual []string
		for _, itemBadge := range item.badges {
			if strings.HasPrefix(itemBadge.kind, "reachability-") {
				actual = append(actual, itemBadge.label)
			}
		}
		if strings.Join(actual, ",") != strings.Join(expectedReachability, ",") {
			t.Fatalf("reachability badges for %q = %#v, want %#v", title, actual, expectedReachability)
		}
		return
	}
	t.Fatalf("expected interactive list item %q", title)
}

func TestScanInteractiveModel_ExplainTopBarUsesQuery(t *testing.T) {
	model := NewExplain(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, "react", sdk.ConsolidatedGraph{}, sdk.New(), nil)
	plain := render.StripANSI(model.View(100, 26))
	if !strings.Contains(plain, "EXPLAIN") || !strings.Contains(plain, "package: react") || strings.Contains(plain, "SCAN") {
		t.Fatalf("expected explain top bar to include command and query, got:\n%s", plain)
	}
}

func TestTopDependedOnComponentStats_UsesTransitiveDependents(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("root", "1.0.0")
	altRoot := sdk.NewPackageRef("alt-root", "1.0.0")
	mid := sdk.NewPackageRef("mid", "1.0.0")
	leaf := sdk.NewPackageRef("leaf", "1.0.0")
	for _, pkg := range []*sdk.Package{root, altRoot, mid, leaf} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	for _, edge := range [][2]string{
		{root.ID, mid.ID},
		{altRoot.ID, mid.ID},
		{mid.ID, leaf.ID},
	} {
		if err := g.AddDependency(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency: %v", err)
		}
	}

	stats := topDependedOnComponentStats(g, 3)
	if len(stats) == 0 {
		t.Fatalf("expected depended-on component stats")
	}
	if stats[0].name != "leaf@1.0.0" || stats[0].dependents != 3 {
		t.Fatalf("expected leaf to include transitive dependents from both roots, got %+v", stats[0])
	}
}

func TestScanInteractiveModel_ComponentTreeExpandsSelectedNode(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackageRef("demo-app", "1.0.0")
	direct := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	transitive := sdk.NewPackage(sdk.Package{Name: "loose-envify", Version: "1.4.0", Scope: "runtime"})
	for _, pkg := range []*sdk.Package{root, direct, transitive} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(root.ID, direct.ID); err != nil {
		t.Fatalf("add root dependency: %v", err)
	}
	if err := g.AddDependency(direct.ID, transitive.ID); err != nil {
		t.Fatalf("add transitive dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(2)
	plain := render.StripANSI(model.View(100, 24))
	if !strings.Contains(plain, "react@18.2.0") {
		t.Fatalf("expected direct dependency in component tree, got:\n%s", plain)
	}
	if strings.Contains(plain, "loose-envify@1.4.0") {
		t.Fatalf("expected transitive dependency to be collapsed initially, got:\n%s", plain)
	}

	model.Move(3)
	model.ToggleSelected()
	plain = render.StripANSI(model.View(100, 24))
	if !strings.Contains(plain, "loose-envify@1.4.0") {
		t.Fatalf("expected expanded transitive dependency, got:\n%s", plain)
	}
	if !strings.Contains(plain, "└─") && !strings.Contains(plain, "├─") {
		t.Fatalf("expected component tree to use box-drawing connectors, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_OverviewDashboardUsesBordersAndBars(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Name: "demo-app", Version: "1.0.0", Ecosystem: "npm"})
	dep := sdk.NewPackage(sdk.Package{Name: "react", Version: "18.2.0", Ecosystem: "npm", Licenses: []sdk.PackageLicense{{Value: "MIT"}}})
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
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	plain := render.StripANSI(model.View(120, 32))
	for _, want := range []string{
		"┌ Components ",
		"┌ Vulnerability Severity ",
		"License Distribution",
		"MIT",
		"██████████████████",
		"Components: 2 | Vulns: 0 | Licenses: 1 | Findings: 0",
		" Tab switch",
		" ← collapse",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected overview dashboard to contain %q, got:\n%s", want, plain)
		}
	}
}

func TestScanInteractiveModel_SourceTreeCollapsesRoot(t *testing.T) {
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, sdk.ConsolidatedGraph{}, sdk.New(), nil)
	model.SelectView(7) // Source is the 7th tab now that Posture sits between Findings and Source
	plain := render.StripANSI(model.View(100, 30))
	if !strings.Contains(plain, "packages: [] (0 items)") {
		t.Fatalf("expected expanded source root, got:\n%s", plain)
	}
	if !strings.Contains(plain, "├─ ▸ packages: [] (0 items)") {
		t.Fatalf("expected source tree to use structured connectors, got:\n%s", plain)
	}
	model.ToggleSelected()
	plain = render.StripANSI(model.View(100, 30))
	if strings.Contains(plain, "packages: [] (0 items)") {
		t.Fatalf("expected collapsed source root to hide packages, got:\n%s", plain)
	}
}

func TestNextInteractiveScopeFilter_UsesUnsetLabel(t *testing.T) {
	if got := nextScopeFilter("development"); got != "unset" {
		t.Fatalf("expected development to cycle to unset, got %q", got)
	}
	if got := nextScopeFilter("unset"); got != "" {
		t.Fatalf("expected unset to cycle back to all scopes, got %q", got)
	}
}

func TestInteractiveStatusBadge_UsesDistinctReadableColors(t *testing.T) {
	direct := statusBadge("direct")
	runtime := badgeView(badge{label: "runtime", kind: "scope-runtime"})
	if direct == runtime {
		t.Fatal("expected direct relationship badge to differ from runtime scope badge")
	}
	if !strings.Contains(direct, render.BgCyan) || !strings.Contains(direct, render.White) {
		t.Fatalf("expected direct badge to use the interactive relationship palette, got %q", direct)
	}

	manifest := statusBadge("manifest")
	if !strings.Contains(manifest, render.BgBlue) || !strings.Contains(manifest, render.Yellow) {
		t.Fatalf("expected manifest badge to use a neutral high-contrast style, got %q", manifest)
	}
}

func TestInteractiveListModel_SearchFiltersVisibleEntries(t *testing.T) {
	model := &listModel{
		title: "Filter Demo",
		items: []listItem{
			{title: "alpha"},
			{title: "react@18.2.0"},
			{title: "zod@3.23.0"},
		},
		searching: true,
	}

	model.AppendSearch("react")
	if !model.searchMatch {
		t.Fatal("expected search to have a match")
	}
	if model.selected != 1 {
		t.Fatalf("expected selection to jump to filtered entry, got %d", model.selected)
	}

	visible := model.visibleItemIndices()
	if len(visible) != 1 || visible[0] != 1 {
		t.Fatalf("expected only the react entry to remain visible, got %#v", visible)
	}

	view := render.StripANSI(model.View(90, 18))
	if strings.Contains(view, "alpha") {
		t.Fatalf("expected non-matching alpha entry to be filtered out, got:\n%s", view)
	}
	if strings.Contains(view, "zod@3.23.0") {
		t.Fatalf("expected non-matching zod entry to be filtered out, got:\n%s", view)
	}
	if !strings.Contains(view, "react@18.2.0") {
		t.Fatalf("expected matching react entry to remain visible, got:\n%s", view)
	}
}

func TestInteractiveListModel_SearchIgnoresDependencyDetailText(t *testing.T) {
	model := &listModel{
		title: "Filter Demo",
		items: []listItem{
			{
				title:   "app@1.0.0",
				details: []string{"Dependencies", "  - syft@1.10.0"},
			},
			{
				title:   "syft@1.10.0",
				details: []string{"Dependencies", "  (none)"},
			},
		},
		searching: true,
	}

	model.AppendSearch("syft")
	visible := model.visibleItemIndices()
	if len(visible) != 1 || visible[0] != 1 {
		t.Fatalf("expected only the syft entry to match, got %#v", visible)
	}
	if model.selected != 1 {
		t.Fatalf("expected selection to jump to the syft entry, got %d", model.selected)
	}
}

func TestBuildLicensesListModel_GroupsByUniqueLicense(t *testing.T) {
	g := sdk.New()
	app := sdk.NewPackageRef("demo-app", "1.0.0")
	react := sdk.NewPackage(sdk.Package{
		Name:     "react",
		Version:  "18.2.0",
		Scope:    "runtime",
		Licenses: []sdk.PackageLicense{{Value: "MIT"}},
	})
	vite := sdk.NewPackage(sdk.Package{
		Name:     "vite",
		Version:  "5.4.0",
		Scope:    "development",
		Licenses: []sdk.PackageLicense{{Value: "MIT"}, {Value: "Apache-2.0"}},
	})
	for _, pkg := range []*sdk.Package{app, react, vite} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add react dependency: %v", err)
	}
	if err := g.AddDependency(app.ID, vite.ID); err != nil {
		t.Fatalf("add vite dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm-detector",
		Origin:       sdk.CoreOrigin,
		Graphs:       engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := NewScan(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.SelectView(4) // Licenses (1: Overview, 2: Components, 3: Vulns, 4: Licenses)
	list := model.buildLicensesListModel()

	if len(list.items) != 2 {
		t.Fatalf("expected 2 unique license rows, got %d", len(list.items))
	}
	plain := render.StripANSI(list.View(100, 28))
	for _, want := range []string{
		"Licenses (2)",
		"Apache-2.0",
		"MIT",
		"Components (1)",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected license view to contain %q, got:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "react@18.2.0  MIT") {
		t.Fatalf("expected licenses tab to group by license instead of package, got:\n%s", plain)
	}
	if !strings.Contains(plain, "vite@5.4.0 [development]") {
		t.Fatalf("expected license details to list packages using the selected license, got:\n%s", plain)
	}
}

func TestNewDiffInteractiveModel_ComponentsTabGroupsByStatusByDefault(t *testing.T) {
	model := NewDiff(output.DiffResponse{
		Results: output.DiffResults{Manifests: []output.DiffManifestResult{
			{Status: "changed", Path: "b", PackageManager: "npm", Added: []output.DiffPackageChange{{Package: output.PackageRef{Name: "x"}}}},
			{Status: "added", Path: "c", PackageManager: "npm", Added: []output.DiffPackageChange{{Package: output.PackageRef{Name: "y"}}}},
			{Status: "removed", Path: "a", PackageManager: "npm", Removed: []output.DiffPackageChange{{Package: output.PackageRef{Name: "z"}}}},
		}},
	}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})

	model.SelectView(2) // Components

	list := model.List()
	if list == nil {
		t.Fatalf("expected components list to be built")
	}
	// Default grouping is "status": groups appear in Added / Changed / Removed order.
	// Each group is followed by its members. Two of the inputs are status=added
	// (one from `.Added` on the "added" manifest, one from `.Added` on the
	// "changed" manifest), one is status=removed.
	if len(list.items) < 4 {
		t.Fatalf("expected at least 4 items (3 groups + members), got %d", len(list.items))
	}
	if got, want := list.items[0].title, "Added (2)"; got != want {
		t.Fatalf("expected first group %q, got %q", want, got)
	}
	// Verify removed group exists somewhere later.
	foundRemoved := false
	for _, it := range list.items {
		if strings.HasPrefix(it.title, "Removed (") {
			foundRemoved = true
			break
		}
	}
	if !foundRemoved {
		t.Fatalf("expected a Removed group, got items: %+v", list.items)
	}
}

func TestNewDiffInteractiveModel_ComponentsCycleGroupingAxis(t *testing.T) {
	model := NewDiff(output.DiffResponse{
		Comparison: output.DiffComparison{Base: "base", Head: "head"},
		Results: output.DiffResults{Manifests: []output.DiffManifestResult{{
			Status:         "changed",
			Path:           "package.json",
			PackageManager: "npm",
			Ecosystem:      "npm",
			Added:          []output.DiffPackageChange{{Package: output.PackageRef{Name: "zod", Version: "3.23.0"}}},
			Removed:        []output.DiffPackageChange{{Package: output.PackageRef{Name: "left-pad", Version: "1.3.0"}}},
			Changed:        []output.DiffChangedPackage{{Before: output.PackageRef{Name: "react", Version: "18.2.0"}, After: output.PackageRef{Name: "react", Version: "19.0.0"}}},
		}}},
		Summary: output.DiffSummary{AddedPackageCount: 1, RemovedPackageCount: 1, ChangedPackageCount: 1},
	}, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})

	model.SelectView(2) // Components

	plain := render.StripANSI(model.View(140, 40))
	// Default grouping = status. All three package changes should be visible.
	if !strings.Contains(plain, "zod@3.23.0") {
		t.Fatalf("expected components tab to show added package (zod), got:\n%s", plain)
	}
	if !strings.Contains(plain, "left-pad@1.3.0") {
		t.Fatalf("expected components tab to show removed package (left-pad), got:\n%s", plain)
	}
	if !strings.Contains(plain, "Group: Status") {
		t.Fatalf("expected default group to be Status, got:\n%s", plain)
	}

	// Cycle grouping: Status -> Manifest. All three changes still visible
	// (grouping is structural, not a filter).
	model.CycleGroup()
	plain = render.StripANSI(model.View(140, 40))
	if !strings.Contains(plain, "Group: Manifest") {
		t.Fatalf("expected group to cycle to Manifest, got:\n%s", plain)
	}
	if !strings.Contains(plain, "zod@3.23.0") {
		t.Fatalf("expected manifest-group to still show zod, got:\n%s", plain)
	}
	if !strings.Contains(plain, "left-pad@1.3.0") {
		t.Fatalf("expected manifest-group to still show left-pad, got:\n%s", plain)
	}
}
