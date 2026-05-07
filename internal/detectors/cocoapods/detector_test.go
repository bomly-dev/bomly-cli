package cocoapods

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerCocoaPods,
		Ecosystem:       sdk.EcosystemSwift,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := g.Package("AppCenter/Analytics@5.0.6")
	if !ok {
		t.Fatal("expected AppCenter/Analytics package")
	}
	if pkg.Scope != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", pkg.Scope)
	}
}

func TestDepGraphFromLockParsesPodsAndDependencies(t *testing.T) {
	raw := []byte(`PODS:
  - Alamofire (5.10.2)
  - AppCenter/Analytics (5.0.6):
    - AppCenter/Core
  - AppCenter/Core (5.0.6)
DEPENDENCIES:
  - Alamofire (~> 5.10)
  - AppCenter/Analytics
SPEC CHECKSUMS:
  Alamofire: abc123
  AppCenter: def456
`)
	g, err := depGraphFromLock(raw)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := g.Package("root")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.Dependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two root dependencies, got %#v", deps)
	}
	analytics, ok := g.Package("AppCenter/Analytics@5.0.6")
	if !ok {
		t.Fatal("expected AppCenter/Analytics package")
	}
	if analytics.Scope != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", analytics.Scope)
	}
	children, err := g.Dependencies(analytics.ID)
	if err != nil {
		t.Fatalf("analytics dependencies: %v", err)
	}
	if len(children) != 1 || children[0].Name != "AppCenter/Core" {
		t.Fatalf("expected AppCenter/Core dependency, got %#v", children)
	}
	if analytics.PURL != "pkg:cocoapods/AppCenter%2FAnalytics@5.0.6" {
		t.Fatalf("unexpected purl %q", analytics.PURL)
	}
}
