package tui

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
	tea "github.com/charmbracelet/bubbletea"
)

func newScanModelWithPosture(t *testing.T, repo string, score float64) *scanModel {
	t.Helper()
	g := sdk.New()
	root := sdk.NewDependencyRef("demo-app", "1.0.0")
	const libPURL = "pkg:npm/lib@1.0.0"
	dep := sdk.NewDependency(sdk.Dependency{Name: "lib", Version: "1.0.0", PURL: libPURL})
	registry := sdk.NewPackageRegistry()
	regLib := registry.Ensure(libPURL)
	regLib.Name = "lib"
	regLib.Version = "1.0.0"
	regLib.Scorecard = newTestScorecardTUI(repo, score,
		sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 2, Reason: "off"},
		sdk.PackageScorecardCheck{Name: "Code-Review", Score: 8, Reason: "ok"},
	)
	for _, pkg := range []*sdk.Dependency{root, dep} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := g.AddEdge(root.ID, dep.ID); err != nil {
		t.Fatalf("add dep: %v", err)
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
	return NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithRegistry(registry).WithEnrichEnabled(true)
}

func TestTabSeven_SwitchesToPostureTab(t *testing.T) {
	t.Parallel()
	model := newScanModelWithPosture(t, "github.com/example/lib", 4.0)
	wrapper := &teaModel{inner: model, width: 160, height: 40}

	if _, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}}); model.ActiveTabID() != string(interactiveScanViewSource) {
		t.Errorf("expected 7 to select Source tab; got %q", model.ActiveTabID())
	}
}

func TestTabSix_SwitchesToPostureTab(t *testing.T) {
	t.Parallel()
	model := newScanModelWithPosture(t, "github.com/example/lib", 4.0)
	wrapper := &teaModel{inner: model, width: 160, height: 40}

	if _, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}}); model.ActiveTabID() != string(interactiveScanViewPosture) {
		t.Errorf("expected 6 to select Posture tab; got %q", model.ActiveTabID())
	}
}

func TestEnter_FocusesDetailsPane(t *testing.T) {
	t.Parallel()
	model := newScanModelWithPosture(t, "github.com/example/lib", 4.0)
	model.SelectView(6) // Posture
	wrapper := &teaModel{inner: model, width: 160, height: 40}

	if model.IsDetailsFocused() {
		t.Fatal("focus should start on the main list")
	}

	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyEnter})
	wrapper = updated.(*teaModel)
	if !model.IsDetailsFocused() {
		t.Fatal("Enter should focus the details pane")
	}

	// Render should mark the active pane.
	plain := render.StripANSI(wrapper.View())
	if !strings.Contains(plain, "● Repository Posture") {
		t.Errorf("expected the focused pane to render a focus marker; got:\n%s", plain)
	}

	// Esc returns focus to the list rather than engaging the quit prompt.
	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyEsc})
	wrapper = updated.(*teaModel)
	if model.IsDetailsFocused() {
		t.Fatal("Esc should blur the details pane")
	}
	if wrapper.confirmQuit {
		t.Fatal("Esc should not trigger quit confirmation while details pane was focused")
	}
}

func TestArrowKeys_ScrollDetailsWhileFocused(t *testing.T) {
	t.Parallel()
	model := newScanModelWithPosture(t, "github.com/example/lib", 4.0)
	model.SelectView(6) // Posture (rich details with multi-line check list)
	wrapper := &teaModel{inner: model, width: 160, height: 40}

	// Focus the details pane via Enter.
	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyEnter})
	wrapper = updated.(*teaModel)

	prevDetailOffset := model.List().detailOffset
	prevSelected := model.List().selected

	// Down arrow while focused must scroll the details, not move the list.
	updated, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyDown})
	wrapper = updated.(*teaModel)
	if model.List().detailOffset <= prevDetailOffset {
		t.Errorf("expected details offset to advance with arrow down while focused; got %d", model.List().detailOffset)
	}
	if model.List().selected != prevSelected {
		t.Errorf("list selection must not move while details pane is focused; got %d (was %d)",
			model.List().selected, prevSelected)
	}

	// Blur and confirm down arrow goes back to moving the list.
	if _, _ = wrapper.Update(tea.KeyMsg{Type: tea.KeyEsc}); model.IsDetailsFocused() {
		t.Fatal("Esc should blur focus")
	}
}

func TestTabCycle_ResetsDetailsFocus(t *testing.T) {
	t.Parallel()
	model := newScanModelWithPosture(t, "github.com/example/lib", 4.0)
	model.SelectView(6)
	model.FocusDetails()
	if !model.IsDetailsFocused() {
		t.Fatal("focus precondition failed")
	}
	model.CycleView()
	if model.IsDetailsFocused() {
		t.Error("CycleView must reset detail focus so the user does not land in a stale pane")
	}
}

func TestPostureGrouping_ByCheckRendersFailingFirst(t *testing.T) {
	t.Parallel()
	g := sdk.New()
	rootA := sdk.NewDependencyRef("app", "1.0.0")
	const aPURL = "pkg:npm/a@1"
	const bPURL = "pkg:npm/b@1"
	a := sdk.NewDependency(sdk.Dependency{Name: "a", Version: "1", PURL: aPURL})
	b := sdk.NewDependency(sdk.Dependency{Name: "b", Version: "1", PURL: bPURL})
	registry := sdk.NewPackageRegistry()
	regA := registry.Ensure(aPURL)
	regA.Name = "a"
	regA.Version = "1"
	regA.Scorecard = newTestScorecardTUI("github.com/example/a", 6.0,
		sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 1},
		sdk.PackageScorecardCheck{Name: "Code-Review", Score: 9},
	)
	regB := registry.Ensure(bPURL)
	regB.Name = "b"
	regB.Version = "1"
	regB.Scorecard = newTestScorecardTUI("github.com/example/b", 4.0,
		sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 0},
		sdk.PackageScorecardCheck{Name: "Code-Review", Score: 7},
	)
	for _, pkg := range []*sdk.Dependency{rootA, a, b} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := g.AddEdge(rootA.ID, a.ID); err != nil {
		t.Fatalf("dep a: %v", err)
	}
	if err := g.AddEdge(rootA.ID, b.ID); err != nil {
		t.Fatalf("dep b: %v", err)
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
	model := NewScan(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, graphValue, nil).WithRegistry(registry).WithEnrichEnabled(true)
	model.SelectView(6)

	// Cycle the group via `g`.
	wrapper := &teaModel{inner: model, width: 200, height: 60}
	updated, _ := wrapper.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	wrapper = updated.(*teaModel)

	plain := render.StripANSI(wrapper.View())
	// Header should show "Checks (N)" once grouped by check.
	if !strings.Contains(plain, "Checks (2)") {
		t.Errorf("expected Checks (2) header in check-grouped view; got:\n%s", plain)
	}
	// Branch-Protection (2 failing) must sort before Code-Review (0 failing).
	bpIdx := strings.Index(plain, "Branch-Protection")
	crIdx := strings.Index(plain, "Code-Review")
	if bpIdx < 0 || crIdx < 0 {
		t.Fatalf("expected both check group headers to render; got:\n%s", plain)
	}
	if bpIdx > crIdx {
		t.Errorf("expected top-failing Branch-Protection to render before Code-Review; got:\n%s", plain)
	}
	// Group counters should reflect 2 failing for Branch-Protection.
	if !strings.Contains(plain, "2 failing") {
		t.Errorf("expected Branch-Protection group to show '2 failing'; got:\n%s", plain)
	}
}

func TestPostureDiffGrouping_ByCheckRegressionsFirst(t *testing.T) {
	t.Parallel()
	results := output.DiffDependencyResults{
		Changed: []output.DiffChangedPackage{
			{
				Before: output.PackageRef{Name: "a", Scorecard: newTestScorecardTUI("github.com/a/repo", 7.0,
					sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 9},
					sdk.PackageScorecardCheck{Name: "Code-Review", Score: 8},
				)},
				After: output.PackageRef{Name: "a", Scorecard: newTestScorecardTUI("github.com/a/repo", 5.0,
					sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 3}, // regression
					sdk.PackageScorecardCheck{Name: "Code-Review", Score: 9},       // improvement
				)},
			},
		},
	}
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
		Results:    output.DiffResults{Dependencies: results},
	}
	model := NewDiff(payload, sdk.ConsolidatedGraph{}, sdk.ConsolidatedGraph{})
	model.SelectView(6)
	model.CycleGroup()

	wrapper := &teaModel{inner: model, width: 200, height: 60}
	plain := render.StripANSI(wrapper.View())
	if !strings.Contains(plain, "Branch-Protection") {
		t.Errorf("expected Branch-Protection group in check view; got:\n%s", plain)
	}
	if !strings.Contains(plain, "1 ↓ regressions") {
		t.Errorf("expected Branch-Protection group to count one regression; got:\n%s", plain)
	}
	bpIdx := strings.Index(plain, "Branch-Protection")
	crIdx := strings.Index(plain, "Code-Review")
	if bpIdx < 0 || crIdx < 0 {
		t.Fatalf("expected both groups; got:\n%s", plain)
	}
	if bpIdx > crIdx {
		t.Errorf("expected regressing Branch-Protection to render above Code-Review; got:\n%s", plain)
	}
}
