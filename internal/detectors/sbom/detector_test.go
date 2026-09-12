package sbom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestDetectorResolveGraph_SPDXJSON(t *testing.T) {
	path := writeSBOMFixture(t, sbom.TargetSPDX23JSON)
	result := resolveFixture(t, path)
	verifyResolvedGraph(t, result, "react@18.2.0")
}

func TestDetectorResolveGraph_CycloneDXJSON(t *testing.T) {
	path := writeSBOMFixture(t, sbom.TargetCycloneDX16JSON)
	result := resolveFixture(t, path)
	verifyResolvedGraph(t, result, "react@18.2.0")
}

func TestDetectorResolveGraph_NormalizesImportedComponentIDs(t *testing.T) {
	doc := &sbom.Document{
		Components: []sbom.Component{
			{ID: "SPDXRef-demo-app-1.0.0", Name: "demo-app", Version: "1.0.0"},
			{ID: "SPDXRef-react-18.2.0", Name: "react", Version: "18.2.0"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "SPDXRef-demo-app-1.0.0", DependsOn: []string{"SPDXRef-react-18.2.0"}},
		},
	}
	data, err := sbom.MarshalJSON(doc, sbom.TargetSPDX23JSON, sbom.EncodeOptions{Pretty: true})
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
	deps, err := g.DirectDependencies(testnodes.ID(g, "demo-app@1.0.0"))
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || !testnodes.Is(deps[0], "react@18.2.0") {
		t.Fatalf("expected normalized dependency edge, got %#v", deps)
	}
}

func TestDetectorResolveGraph_PrefersImportedPURLIdentity(t *testing.T) {
	g := sdk.New()
	app := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "demo-app",
		Version:        "1.0.0",
		PURL:           "pkg:npm/demo-app@1.0.0"},
	})

	react := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "react",
		Version:        "18.2.0",
		PURL:           "pkg:npm/react@18.2.0"},
	})

	for _, pkg := range []*sdk.DependencyNode{app, react} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package %s: %v", pkg.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	data, err := sbom.MarshalDepGraphJSON(g, sbom.TargetSPDX23JSON, sbom.BuildOptions{
		DocumentName: "demo",
		Created:      time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	}, sbom.EncodeOptions{Pretty: true})
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
	reactPkg, ok := resolvedGraph.DependencyNode("pkg:npm/react@18.2.0")
	if !ok || reactPkg == nil {
		t.Fatalf("expected PURL-normalized react package, got %s", resolvedGraph.PrettyString())
	}
	if !testnodes.Is(reactPkg, "pkg:npm/react@18.2.0") {
		t.Fatalf("expected react purl to be preserved, got %q", reactPkg.NodeID())
	}
	if reactPkg.Ecosystem != "npm" || reactPkg.PackageManager != "npm" {
		t.Fatalf("expected react identity to be restored from SBOM, got ecosystem=%q packageManager=%q", reactPkg.Ecosystem, reactPkg.PackageManager)
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

// TestDetectorResolveGraph_RejectsSyftJSON asserts that syft-format JSON SBOMs
// yield the actionable conversion error. The fixture is handcrafted so the test
// runs identically under the default and bomly_external_syft build tags.
func TestDetectorResolveGraph_RejectsSyftJSON(t *testing.T) {
	syftJSON := []byte(`{"artifacts":[],"artifactRelationships":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"syft","version":"1.0.0"},"schema":{"version":"16.0.34","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}}`)
	if _, err := sbom.DetectJSONTarget(syftJSON); !errors.Is(err, sbom.ErrUnsupportedFormat) {
		t.Fatalf("fixture must be an unsupported format, got %v", err)
	}

	path := filepath.Join(t.TempDir(), "input.syft.json")
	if err := os.WriteFile(path, syftJSON, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := (Detector{}).ResolveGraph(context.Background(), requestForSBOMPath(path))
	if err == nil || !errors.Is(err, sbom.ErrUnsupportedFormat) {
		t.Fatalf("ResolveGraph() error = %v, want wrapped sbom.ErrUnsupportedFormat", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("ResolveGraph() error %q missing the file path", err.Error())
	}
}

func TestDetectorResolveGraph_RejectsOversizedSBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxSBOMFileBytes+1); err != nil {
		t.Fatal(err)
	}

	_, err := (Detector{}).ResolveGraph(context.Background(), requestForSBOMPath(path))
	if err == nil || !strings.Contains(err.Error(), "exceeds the 256 MiB limit") {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if !errors.Is(err, system.ErrInputTooLarge) {
		t.Fatalf("ResolveGraph() error = %v, want wrapped system.ErrInputTooLarge", err)
	}
}

func resolveFixture(t *testing.T, path string) sdk.DetectionResult {
	t.Helper()
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), requestForSBOMPath(path))
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	return result
}

func requestForSBOMPath(path string) sdk.DetectionRequest {
	executionTarget := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: path}
	return sdk.DetectionRequest{
		ProjectPath:     path,
		ExecutionTarget: executionTarget,
		Subproject: sdk.Subproject{
			ExecutionTarget:         executionTarget,
			RelativePath:            filepath.Base(path),
			PrimaryDetector:         "sbom-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
			Ecosystem:               sdk.EcosystemSBOM,
		},
		PackageManager: sdk.PackageManagerSBOM,
		Ecosystem:      sdk.EcosystemSBOM,
	}
}

func writeSBOMFixture(t *testing.T, target sbom.Target) string {
	t.Helper()
	g := sdk.New()
	app := testnodes.Ref("demo-app", "1.0.0")
	react := testnodes.Ref("react", "18.2.0")
	for _, pkg := range []*sdk.DependencyNode{app, react} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package: %v", err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	data, err := sbom.MarshalDepGraphJSON(g, target, sbom.BuildOptions{
		DocumentName: "demo",
		Created:      time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	}, sbom.EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func verifyResolvedGraph(t *testing.T, result sdk.DetectionResult, wantDependencyID string) {
	t.Helper()
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if g == nil || g.Size() == 0 {
		t.Fatal("expected resolved graph")
	}
	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && testnodes.Is(pkg, wantDependencyID) {
			return
		}
	}
	t.Fatalf("expected graph to contain stable package id %q, got %s", wantDependencyID, g.PrettyString())
}

// A carrier token this build cannot read reaches the user as a warning, and
// the scopes beside it still reach the graph.
//
// The SDK reads the carrier leniently so an older Bomly does not lose every
// scope to one token a newer one wrote (bomly-dev/bomly-sdk#64). Dropping the
// token silently would leave a user with no way to learn that the document was
// written by a later build; this detector's logger is the channel the ingest
// path has, since the codec has none and the SDK deliberately does not log.
func TestDetectorWarnsAboutUnreadableScopeTokens(t *testing.T) {
	raw := `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "n",
  "documentNamespace": "https://acme.example/spdx/n",
  "creationInfo": {"created": "2026-01-02T03:04:05Z", "creators": ["Tool: t"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-widget",
      "name": "widget",
      "versionInfo": "1.0.0",
      "comment": "bomly:scope=runtime,future-scope",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/widget@1.0.0"}
      ]
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "carrier.spdx.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	core, logs := observer.New(zap.WarnLevel)
	detector := Detector{Logger: zap.New(core)}
	result, err := detector.ResolveGraph(context.Background(), requestForSBOMPath(path))
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", entries)
	}
	if !strings.Contains(entries[0].Message, "scope token") {
		t.Errorf("warning = %q, want it to name the unreadable tokens", entries[0].Message)
	}
	var named bool
	for _, field := range entries[0].Context {
		if field.Key == "tokens" && strings.Contains(fmt.Sprint(field.Interface), "future-scope") {
			named = true
		}
	}
	if !named {
		t.Errorf("warning fields = %+v, want the token itself", entries[0].Context)
	}

	// The scope this build can read still reached the graph: the warning is
	// about what was dropped, not about what was kept.
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	nodes := g.DependencyNodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want the component", len(nodes))
	}
	if len(nodes[0].Scopes) != 1 || nodes[0].Scopes[0] != sdk.ScopeRuntime {
		t.Errorf("scopes = %v, want runtime", nodes[0].Scopes)
	}
}

// A document with a carrier this build reads completely warns about nothing.
func TestDetectorStaysQuietForAReadableCarrier(t *testing.T) {
	path := writeSBOMFixture(t, sbom.TargetSPDX23JSON)
	core, logs := observer.New(zap.WarnLevel)
	detector := Detector{Logger: zap.New(core)}
	if _, err := detector.ResolveGraph(context.Background(), requestForSBOMPath(path)); err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if entries := logs.All(); len(entries) != 0 {
		t.Errorf("warnings = %+v, want none", entries)
	}
}
