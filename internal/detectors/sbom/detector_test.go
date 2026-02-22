package sbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bomlysbom "github.com/bomly-dev/bomly-cli/internal/sbom"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraph_SPDXJSON(t *testing.T) {
	path := writeSBOMFixture(t, bomlysbom.TargetSPDX23JSON)
	result := resolveFixture(t, path)
	verifyResolvedGraph(t, result, "react@18.2.0")
}

func TestDetectorResolveGraph_CycloneDXJSON(t *testing.T) {
	path := writeSBOMFixture(t, bomlysbom.TargetCycloneDX16JSON)
	result := resolveFixture(t, path)
	verifyResolvedGraph(t, result, "react@18.2.0")
}

func TestDetectorResolveGraph_NormalizesImportedComponentIDs(t *testing.T) {
	doc := &bomlysbom.Document{
		Components: []bomlysbom.Component{
			{ID: "SPDXRef-demo-app-1.0.0", Name: "demo-app", Version: "1.0.0"},
			{ID: "SPDXRef-react-18.2.0", Name: "react", Version: "18.2.0"},
		},
		Dependencies: []bomlysbom.Dependency{
			{Ref: "SPDXRef-demo-app-1.0.0", DependsOn: []string{"SPDXRef-react-18.2.0"}},
		},
	}
	data, err := bomlysbom.MarshalJSON(doc, bomlysbom.TargetSPDX23JSON, bomlysbom.EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "manual.spdx.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result := resolveFixture(t, path)
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	deps, err := g.Dependencies("demo-app@1.0.0")
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].ID != "react@18.2.0" {
		t.Fatalf("expected normalized dependency edge, got %#v", deps)
	}
}

func TestDetectorResolveGraph_PrefersImportedPURLIdentity(t *testing.T) {
	g := model.New()
	app := model.NewPackage(model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "demo-app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/demo-app@1.0.0",
	})
	react := model.NewPackage(model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})
	for _, pkg := range []*model.Package{app, react} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package %s: %v", pkg.ID, err)
		}
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	data, err := bomlysbom.MarshalDepGraphJSON(g, bomlysbom.TargetSPDX23JSON, bomlysbom.BuildOptions{
		DocumentName: "demo",
		Created:      time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	}, bomlysbom.EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result := resolveFixture(t, path)
	resolvedGraph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	reactPkg, ok := resolvedGraph.Package("pkg:npm/react@18.2.0")
	if !ok || reactPkg == nil {
		t.Fatalf("expected PURL-normalized react package, got %s", resolvedGraph.PrettyString())
	}
	if reactPkg.PURL != "pkg:npm/react@18.2.0" {
		t.Fatalf("expected react purl to be preserved, got %q", reactPkg.PURL)
	}
	if reactPkg.Ecosystem != "npm" || reactPkg.BuildSystem != "npm" {
		t.Fatalf("expected react identity to be restored from SBOM, got ecosystem=%q buildSystem=%q", reactPkg.Ecosystem, reactPkg.BuildSystem)
	}
}

func TestDetectorResolveGraph_RejectsUnsupportedOrMalformedJSON(t *testing.T) {
	detector := Detector{}
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "unsupported", content: `{"hello":"world"}`, want: "unsupported sbom format"},
		{name: "malformed", content: `{"hello":`, want: "malformed sbom json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := detector.ResolveGraph(context.Background(), requestForSBOMPath(path))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func resolveFixture(t *testing.T, path string) model.DetectionResult {
	t.Helper()
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), requestForSBOMPath(path))
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	return result
}

func requestForSBOMPath(path string) model.DetectionRequest {
	executionTarget := model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: path}
	return model.DetectionRequest{
		ProjectPath:     path,
		ExecutionTarget: executionTarget,
		Subproject: model.Subproject{
			ExecutionTarget:         executionTarget,
			RelativePath:            filepath.Base(path),
			PrimaryDetector:         "sbom-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerSBOM},
			Ecosystem:               model.EcosystemSBOM,
		},
		PackageManager: model.PackageManagerSBOM,
		Ecosystem:      model.EcosystemSBOM,
		Mode:           model.TargetModeFullGraph,
	}
}

func writeSBOMFixture(t *testing.T, target bomlysbom.Target) string {
	t.Helper()
	g := model.New()
	app := model.NewPackageRef("demo-app", "1.0.0")
	react := model.NewPackageRef("react", "18.2.0")
	for _, pkg := range []*model.Package{app, react} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddDependency(app.ID, react.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	data, err := bomlysbom.MarshalDepGraphJSON(g, target, bomlysbom.BuildOptions{
		DocumentName: "demo",
		Created:      time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	}, bomlysbom.EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func verifyResolvedGraph(t *testing.T, result model.DetectionResult, wantDependencyID string) {
	t.Helper()
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if g == nil || g.Size() == 0 {
		t.Fatal("expected resolved graph")
	}
	for _, pkg := range g.Packages() {
		if pkg != nil && pkg.StableID() == wantDependencyID {
			return
		}
	}
	t.Fatalf("expected graph to contain stable package id %q, got %s", wantDependencyID, g.PrettyString())
}
