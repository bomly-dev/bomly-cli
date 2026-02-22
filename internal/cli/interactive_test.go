package cli

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
	tea "github.com/charmbracelet/bubbletea"
)

func TestInteractiveManifestRows_OnlyIncludesManifests(t *testing.T) {
	g := model.New()
	root := model.NewPackageRef("demo-app", "1.0.0")
	direct := model.NewPackageRef("react", "18.2.0")
	transitive := model.NewPackageRef("loose-envify", "1.4.0")
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

	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName:  "npm-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	rows := interactiveManifestRows(consolidated)
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
	g := model.New()
	root := model.NewPackageRef("demo-app", "1.0.0")
	dep := model.NewPackage(model.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := g.AddPackage(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName:  "npm-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.Move(1)
	view := model.View(90, 20)

	plain := stripANSI(view)
	for _, want := range []string{
		"Bomly Interactive Scan: demo-app",
		"Manifest  package-lock.json",
		"Root      demo-app@1.0.0",
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
	model := newDiffInteractiveModel(output.DiffResponse{
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
	})

	view := model.View(100, 18)
	for _, want := range []string{
		"Bomly Interactive Diff: base -> head",
		"package.json (npm)",
		"Manifest changes",
		"Package changes",
		"Added packages",
		"zod@3.23.0",
		"react@19.0.0 (18.2.0 -> 19.0.0)",
	} {
		if !strings.Contains(stripANSI(view), want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "\x1b[") {
		t.Fatalf("expected ANSI styling in view, got:\n%s", view)
	}
}

func TestNewScanInteractiveModel_ViewIncludesGraphSummary(t *testing.T) {
	g := model.New()
	root := model.NewPackageRef("demo-app", "1.0.0")
	dep := model.NewPackage(model.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if err := g.AddPackage(root); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := g.AddPackage(dep); err != nil {
		t.Fatalf("add dep: %v", err)
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName:  "npm-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{
		Name:      "demo-app",
		Path:      "/tmp/demo-app",
		Ecosystem: "npm",
	}, consolidated, graphValue, nil)
	view := model.View(100, 20)
	plain := stripANSI(view)

	for _, want := range []string{
		"Bomly Interactive Scan: demo-app",
		"Manifest  package-lock.json",
		"Direct    1",
		"Transitive 0",
		"Project   /tmp/demo-app",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestInteractivePackageDisplayName_IncludesScope(t *testing.T) {
	pkg := model.NewPackage(model.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	if got := interactivePackageDisplayName(pkg); got != "react@18.2.0 [runtime]" {
		t.Fatalf("expected scoped display name, got %q", got)
	}
}

func TestScanInteractiveModel_MultiManifestNavigation(t *testing.T) {
	g := model.New()
	r1 := model.NewPackageRef("web-app", "1.0.0")
	r2 := model.NewPackageRef("api", "2.0.0")
	c1 := model.NewPackageRef("react", "18.2.0")
	c2 := model.NewPackageRef("zod", "3.23.0")
	for _, pkg := range []*model.Package{r1, r2, c1, c2} {
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
	consolidated := consolidatedForInteractive(t, []model.DetectionResult{
		{
			SubprojectInfo: model.Subproject{
				ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/multi"},
				RelativePath:            ".",
				PrimaryDetector:         "maven-detector",
				DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven},
				Ecosystem:               model.EcosystemMaven,
			},
			DetectorName:  "maven-detector",
			ComponentType: model.NativeComponent,
			Graphs:        scan.SingleGraphContainer(graphFixtureForInteractive(t, r1, c1), model.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}),
		},
		{
			SubprojectInfo: model.Subproject{
				ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/multi"},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
				Ecosystem:               model.EcosystemNPM,
			},
			DetectorName:  "npm-detector",
			ComponentType: model.NativeComponent,
			Graphs:        scan.SingleGraphContainer(graphFixtureForInteractive(t, r2, c2), model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{Name: "multi", Path: "/tmp/multi"}, consolidated, graphValue, nil)
	plain := stripANSI(model.View(100, 20))
	if !strings.Contains(plain, "Manifests 2") {
		t.Fatalf("expected manifest list view, got:\n%s", plain)
	}

	teaModel := &interactiveTeaModel{inner: model, width: 100, height: 20}
	updated, _ := teaModel.Update(tea.KeyMsg{Type: tea.KeyEnter})
	teaModel = updated.(*interactiveTeaModel)
	plain = stripANSI(teaModel.View())
	if !strings.Contains(plain, "Direct") {
		t.Fatalf("expected component view after Enter, got:\n%s", plain)
	}

	updated, _ = teaModel.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	teaModel = updated.(*interactiveTeaModel)
	plain = stripANSI(teaModel.View())
	if !strings.Contains(plain, "Manifests 2") {
		t.Fatalf("expected back navigation to manifest list, got:\n%s", plain)
	}
}

func TestScanInteractiveModel_SingleManifestAutoEntry_NoBackNavigation(t *testing.T) {
	g := model.New()
	r1 := model.NewPackageRef("web-app", "1.0.0")
	c1 := model.NewPackageRef("react", "18.2.0")
	for _, pkg := range []*model.Package{r1, c1} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(r1.ID, c1.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/single"},
			RelativePath:            ".",
			PrimaryDetector:         "maven-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerMaven},
			Ecosystem:               model.EcosystemMaven,
		},
		DetectorName:  "maven-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(graphFixtureForInteractive(t, r1, c1), model.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{Name: "single", Path: "/tmp/single"}, consolidated, graphValue, nil)
	if model.CanGoBack() {
		t.Fatal("expected single-manifest mode to disable back navigation")
	}

	teaModel := &interactiveTeaModel{inner: model, width: 100, height: 20}
	before := stripANSI(teaModel.View())
	updated, _ := teaModel.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	teaModel = updated.(*interactiveTeaModel)
	after := stripANSI(teaModel.View())
	if before != after {
		t.Fatalf("expected back key to have no effect in single-manifest mode")
	}
}

func graphFixtureForInteractive(t *testing.T, root, dep *model.Package) *model.Graph {
	t.Helper()
	g := model.New()
	for _, pkg := range []*model.Package{root, dep} {
		if err := g.AddPackage(pkg.Clone()); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(root.ID, dep.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return g
}

func consolidatedForInteractive(t *testing.T, results []model.DetectionResult) model.ConsolidatedGraph {
	t.Helper()
	consolidated, err := scan.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	return consolidated
}

func TestInteractiveTeaModel_KeyBindings(t *testing.T) {
	inner := &interactiveListModel{
		items: []interactiveListItem{{title: "one"}, {title: "two"}, {title: "three"}},
	}
	model := &interactiveTeaModel{inner: inner, width: 80, height: 20}

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(*interactiveTeaModel)
	if cmd != nil {
		t.Fatalf("expected no command for down key, got %#v", cmd)
	}
	if inner.selected != 1 {
		t.Fatalf("expected selection to move down to 1, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	model = updated.(*interactiveTeaModel)
	if inner.selected != 0 {
		t.Fatalf("expected selection to move back up to 0, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(*interactiveTeaModel)
	if inner.selected != 2 {
		t.Fatalf("expected selection to move to end, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyHome})
	model = updated.(*interactiveTeaModel)
	if inner.selected != 0 {
		t.Fatalf("expected home key to move to top, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(*interactiveTeaModel)
	if inner.selected != 2 {
		t.Fatalf("expected end key to move to bottom, got %d", inner.selected)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*interactiveTeaModel)
	if !model.confirmQuit {
		t.Fatal("expected escape key to request quit confirmation")
	}
}

func TestInteractiveTeaModel_QuitConfirmationCancelsAndConfirms(t *testing.T) {
	model := &interactiveTeaModel{inner: &interactiveListModel{}, width: 80, height: 20}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*interactiveTeaModel)
	if !model.confirmQuit {
		t.Fatal("expected q to open quit confirmation")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*interactiveTeaModel)
	if model.quitting || model.confirmQuit {
		t.Fatal("expected esc to cancel quit confirmation")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*interactiveTeaModel)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(*interactiveTeaModel)
	if !model.quitting {
		t.Fatal("expected enter to confirm quit")
	}
}

func TestInteractiveTeaModel_QuitConfirmationOverlaysAndClears(t *testing.T) {
	inner := &interactiveListModel{
		title:          "Demo",
		summary:        []string{"Packages  2"},
		navigationHelp: "help",
		items: []interactiveListItem{
			{title: "alpha"},
			{title: "beta"},
		},
	}
	model := &interactiveTeaModel{inner: inner, width: 80, height: 16}

	before := stripANSI(model.View())
	if !strings.Contains(before, " Demo ") {
		t.Fatalf("expected header to be visible before quit confirmation, got:\n%s", before)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(*interactiveTeaModel)
	during := stripANSI(model.View())
	if !strings.Contains(during, " Demo ") {
		t.Fatalf("expected header to remain visible during quit confirmation, got:\n%s", during)
	}
	if !strings.Contains(during, "Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels.") {
		t.Fatalf("expected quit confirmation message, got:\n%s", during)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(*interactiveTeaModel)
	after := stripANSI(model.View())
	if strings.Contains(after, "Exit Bomly interactive mode? Enter confirms, Esc/Backspace cancels.") {
		t.Fatalf("expected quit confirmation message to clear after cancel, got:\n%s", after)
	}
	if !strings.Contains(after, " Demo ") {
		t.Fatalf("expected header to remain visible after cancel, got:\n%s", after)
	}
}

func TestInteractiveTeaModel_SearchJump(t *testing.T) {
	inner := &interactiveListModel{
		items: []interactiveListItem{
			{title: "alpha"},
			{title: "react@18.2.0"},
			{title: "zod@3.23.0"},
		},
	}
	model := &interactiveTeaModel{inner: inner, width: 80, height: 20}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	model = updated.(*interactiveTeaModel)
	if !inner.IsSearching() {
		t.Fatal("expected search mode to start")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r', 'e', 'a'}})
	model = updated.(*interactiveTeaModel)
	if inner.selected != 1 {
		t.Fatalf("expected search to jump to index 1, got %d", inner.selected)
	}
	if inner.searchQuery != "rea" {
		t.Fatalf("expected search query to be rea, got %q", inner.searchQuery)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_ = updated.(*interactiveTeaModel)
	if inner.IsSearching() {
		t.Fatal("expected enter to finish search mode")
	}
}

func TestInteractiveListModel_ViewIncludesSearchPrompt(t *testing.T) {
	model := &interactiveListModel{
		title:          "Search Demo",
		summary:        []string{"Packages  3"},
		navigationHelp: "help",
		items:          []interactiveListItem{{title: "alpha"}, {title: "react@18.2.0"}, {title: "zod@3.23.0"}},
		searching:      true,
		searchQuery:    "react",
		searchMatch:    true,
	}

	view := stripANSI(model.View(90, 18))
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
	items := []interactiveListItem{{
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
	model := &interactiveListModel{
		title:          "Scroll Demo",
		navigationHelp: "help",
		items:          items,
	}

	before := stripANSI(model.View(80, 12))
	if !strings.Contains(before, "detail-01") {
		t.Fatalf("expected initial details to include first line, got:\n%s", before)
	}
	if strings.Contains(before, "detail-09") {
		t.Fatalf("expected initial details to be clipped before detail-09, got:\n%s", before)
	}

	model.ScrollDetails(4)
	after := stripANSI(model.View(80, 12))
	if strings.Contains(after, "detail-01") {
		t.Fatalf("expected scrolled details to move past detail-01, got:\n%s", after)
	}
	if !strings.Contains(after, "detail-09") {
		t.Fatalf("expected scrolled details to include detail-09, got:\n%s", after)
	}
}

func TestInteractiveTeaModel_PageDownScrollsDetailPane(t *testing.T) {
	inner := &interactiveListModel{
		title:          "Scroll Demo",
		navigationHelp: "help",
		items: []interactiveListItem{{
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
	model := &interactiveTeaModel{inner: inner, width: 80, height: 12}

	before := stripANSI(model.View())
	if !strings.Contains(before, "detail-01") {
		t.Fatalf("expected initial details to include first line, got:\n%s", before)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(*interactiveTeaModel)
	after := stripANSI(model.View())
	if strings.Contains(after, "detail-01") {
		t.Fatalf("expected page-down to scroll details, got:\n%s", after)
	}
	if !strings.Contains(after, "detail-09") {
		t.Fatalf("expected page-down to reveal later detail lines, got:\n%s", after)
	}
}

func TestInteractiveListModel_HelpWrapsAcrossMultipleLines(t *testing.T) {
	model := &interactiveListModel{
		title:          "Help Wrap Demo",
		navigationHelp: "Use page up and page down to scroll expanded details. Use q to quit interactive mode.",
		filterHelp:     "Use slash to search and filter.",
		items:          []interactiveListItem{{title: "alpha", details: []string{"detail"}}},
	}

	view := stripANSI(model.View(60, 14))
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
	g := model.New()
	root := model.NewPackageRef("demo-app", "1.0.0")
	runtimeDep := model.NewPackage(model.Package{Name: "react", Version: "18.2.0", Scope: "runtime"})
	devDep := model.NewPackage(model.Package{Name: "vitest", Version: "2.0.0", Scope: "development"})
	for _, pkg := range []*model.Package{root, runtimeDep, devDep} {
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

	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName:  "npm-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)

	plain := stripANSI(model.View(100, 20))
	if !strings.Contains(plain, "react@18.2.0") || !strings.Contains(plain, "vitest@2.0.0") {
		t.Fatalf("expected scoped component rows, got:\n%s", plain)
	}

	model.CycleScopeFilter()
	plain = stripANSI(model.View(100, 20))
	if !strings.Contains(plain, "react@18.2.0") || strings.Contains(plain, "vitest@2.0.0") {
		t.Fatalf("expected runtime scope filter to keep only runtime packages, got:\n%s", plain)
	}

	model.CycleRelationshipFilter()
	model.CycleRelationshipFilter()
	plain = stripANSI(model.View(100, 20))
	if strings.Contains(plain, "demo-app@1.0.0  ROOT") || !strings.Contains(plain, "react@18.2.0") {
		t.Fatalf("expected direct relationship filter to hide root row, got:\n%s", plain)
	}
}

func TestNextInteractiveScopeFilter_UsesUnsetLabel(t *testing.T) {
	if got := nextInteractiveScopeFilter("development"); got != "unset" {
		t.Fatalf("expected development to cycle to unset, got %q", got)
	}
	if got := nextInteractiveScopeFilter("unset"); got != "" {
		t.Fatalf("expected unset to cycle back to all scopes, got %q", got)
	}
}

func TestInteractiveStatusBadge_UsesDistinctReadableColors(t *testing.T) {
	direct := interactiveStatusBadge("direct")
	runtime := interactiveBadgeView(interactiveBadge{label: "runtime", kind: "scope-runtime"})
	if direct == runtime {
		t.Fatal("expected direct relationship badge to differ from runtime scope badge")
	}
	if !strings.Contains(direct, ansiBgCyan) || !strings.Contains(direct, ansiWhite) {
		t.Fatalf("expected direct badge to use the interactive relationship palette, got %q", direct)
	}

	manifest := interactiveStatusBadge("manifest")
	if !strings.Contains(manifest, ansiBgBlue) || !strings.Contains(manifest, ansiYellow) {
		t.Fatalf("expected manifest badge to use a neutral high-contrast style, got %q", manifest)
	}
}

func TestInteractiveListModel_SearchFiltersVisibleEntries(t *testing.T) {
	model := &interactiveListModel{
		title: "Filter Demo",
		items: []interactiveListItem{
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

	view := stripANSI(model.View(90, 18))
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
	model := &interactiveListModel{
		title: "Filter Demo",
		items: []interactiveListItem{
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
	g := model.New()
	app := model.NewPackageRef("demo-app", "1.0.0")
	react := model.NewPackage(model.Package{
		Name:     "react",
		Version:  "18.2.0",
		Scope:    "runtime",
		Licenses: []model.PackageLicense{{Value: "MIT"}},
	})
	vite := model.NewPackage(model.Package{
		Name:     "vite",
		Version:  "5.4.0",
		Scope:    "development",
		Licenses: []model.PackageLicense{{Value: "MIT"}, {Value: "Apache-2.0"}},
	})
	for _, pkg := range []*model.Package{app, react, vite} {
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

	consolidated := consolidatedForInteractive(t, []model.DetectionResult{{
		SubprojectInfo: model.Subproject{
			ExecutionTarget:         model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: "/tmp/demo-app"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		},
		DetectorName:  "npm-detector",
		ComponentType: model.NativeComponent,
		Graphs:        scan.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
	}})
	graphValue, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	model := newScanInteractiveModel(output.ProjectDescriptor{Name: "demo-app", Path: "/tmp/demo-app"}, consolidated, graphValue, nil)
	model.activeView = interactiveScanViewLicenses
	list := model.buildLicensesListModel()

	if len(list.items) != 2 {
		t.Fatalf("expected 2 unique license rows, got %d", len(list.items))
	}
	plain := stripANSI(list.View(100, 20))
	for _, want := range []string{
		"Unique licenses 2",
		"Apache-2.0",
		"MIT",
		"Packages Using This License",
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

func TestNewDiffInteractiveModel_OrdersRemovedAddedChanged(t *testing.T) {
	model := newDiffInteractiveModel(output.DiffResponse{
		Results: output.DiffResults{Manifests: []output.DiffManifestResult{
			{Status: "changed", Path: "b", PackageManager: "npm"},
			{Status: "added", Path: "c", PackageManager: "npm"},
			{Status: "removed", Path: "a", PackageManager: "npm"},
		}},
	})

	if got, want := model.items[0].subtitle, "removed"; got != want {
		t.Fatalf("expected first item status %q, got %q", want, got)
	}
	if got, want := model.items[1].subtitle, "added"; got != want {
		t.Fatalf("expected second item status %q, got %q", want, got)
	}
	if got, want := model.items[2].subtitle, "changed"; got != want {
		t.Fatalf("expected third item status %q, got %q", want, got)
	}
}
