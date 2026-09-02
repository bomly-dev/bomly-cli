package nuget

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/nodes"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerNuGet,
		Ecosystem:       sdk.EcosystemDotNet,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := testnodes.Find(g, "Newtonsoft.Json@13.0.3")
	if !ok {
		t.Fatal("expected Newtonsoft.Json package")
	}
	if !testnodes.Is(pkg, "pkg:nuget/Newtonsoft.Json@13.0.3") {
		t.Fatalf("unexpected purl %q", pkg.NodeID())
	}
}

func TestDepGraphFromLockMultiTarget(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc",
        "dependencies": {"System.Text.Json": "8.0.0"}
      },
      "System.Text.Json": {
        "type": "Transitive",
        "resolved": "8.0.0"
      }
    },
    "net472": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "dependencies": {"System.Text.Json": "8.0.0"}
      }
    }
  }
}`)

	g, err := depGraphFromLock(raw)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := testnodes.Find(g, "root")
	if !ok {
		t.Fatal("expected root package")
	}
	depsNodes, err := g.DirectDependencies(root.NodeID())
	deps := nodes.DependenciesOf(depsNodes)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "Newtonsoft.Json" {
		t.Fatalf("expected root to depend on Newtonsoft.Json, got %#v", deps)
	}
	systemText, ok := testnodes.Find(g, "System.Text.Json@8.0.0")
	if !ok {
		t.Fatal("expected System.Text.Json package")
	}
	if string(mustDep(t, systemText).PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected transitive runtime scope, got %q", string(mustDep(t, systemText).PrimaryScope()))
	}
}

func TestDepGraphFromPackagesConfig(t *testing.T) {
	raw := []byte(`<packages><package id="NUnit" version="4.2.2" targetFramework="net48" /></packages>`)
	g, err := depGraphFromPackagesConfig(raw)
	if err != nil {
		t.Fatalf("depGraphFromPackagesConfig() error = %v", err)
	}
	pkg, ok := testnodes.Find(g, "NUnit@4.2.2")
	if !ok {
		t.Fatal("expected NUnit package")
	}
	if !testnodes.Is(pkg, "pkg:nuget/NUnit@4.2.2") {
		t.Fatalf("unexpected purl %q", pkg.NodeID())
	}
}

func TestDepGraphFromProjectFiles(t *testing.T) {
	projectDir := t.TempDir()
	projectPath := filepath.Join(projectDir, "example.csproj")
	raw := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
    <PackageReference Include="Newtonsoft.Json">
      <Version>13.0.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>`)
	if err := os.WriteFile(projectPath, raw, 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	g, err := depGraphFromProjectFiles([]string{projectPath})
	if err != nil {
		t.Fatalf("depGraphFromProjectFiles() error = %v", err)
	}
	for _, want := range []string{"System.Runtime.Extensions@4.3.0", "Newtonsoft.Json@13.0.3"} {
		pkg, ok := testnodes.Find(g, want)
		if !ok {
			t.Fatalf("expected package %q", want)
		}
		if string(mustDep(t, pkg).PrimaryScope()) != string(sdk.ScopeRuntime) {
			t.Fatalf("expected runtime scope for %q, got %q", want, string(mustDep(t, pkg).PrimaryScope()))
		}
	}
}

func TestDetectorResolveGraphAttachesProjectAndConfigLocations(t *testing.T) {
	projectDir := t.TempDir()
	nestedDir := filepath.Join(projectDir, "src", "app")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	projectPath := filepath.Join(nestedDir, "example.csproj")
	raw := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="System.Runtime.Extensions" Version="4.3.0" />
    <PackageReference Include="Newtonsoft.Json">
      <Version>13.0.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>`)
	if err := os.WriteFile(projectPath, raw, 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     projectDir,
		PackageManager:  sdk.PackageManagerNuGet,
		Ecosystem:       sdk.EcosystemDotNet,
		ExecutionTarget: sdk.ExecutionTarget{Location: projectDir},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	systemRuntime, ok := testnodes.Find(g, "System.Runtime.Extensions@4.3.0")
	if !ok || len(mustDep(t, systemRuntime).Locations) == 0 || mustDep(t, systemRuntime).Locations[0].Position == nil || mustDep(t, systemRuntime).Locations[0].Position.Line != 3 {
		t.Fatalf("System.Runtime.Extensions locations = %#v, want inline PackageReference line 3", mustDep(t, systemRuntime).Locations)
	}
	newtonsoft, ok := testnodes.Find(g, "Newtonsoft.Json@13.0.3")
	if !ok || len(mustDep(t, newtonsoft).Locations) == 0 || mustDep(t, newtonsoft).Locations[0].Position == nil || mustDep(t, newtonsoft).Locations[0].Position.Line != 5 {
		t.Fatalf("Newtonsoft.Json locations = %#v, want Version element line 5", mustDep(t, newtonsoft).Locations)
	}
	if mustDep(t, newtonsoft).Locations[0].RealPath != "src/app/example.csproj" {
		t.Fatalf("Newtonsoft.Json location path = %#v, want nested project path", mustDep(t, newtonsoft).Locations[0])
	}
}

func TestDetectorResolveGraphAttachesPackagesConfigLocations(t *testing.T) {
	projectDir := t.TempDir()
	raw := []byte(`<packages>
  <package id="NUnit" version="4.2.2" targetFramework="net48" />
</packages>`)
	if err := os.WriteFile(filepath.Join(projectDir, "packages.config"), raw, 0o644); err != nil {
		t.Fatalf("write packages.config: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     projectDir,
		PackageManager:  sdk.PackageManagerNuGet,
		Ecosystem:       sdk.EcosystemDotNet,
		ExecutionTarget: sdk.ExecutionTarget{Location: projectDir},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	nunit, ok := testnodes.Find(g, "NUnit@4.2.2")
	if !ok || len(mustDep(t, nunit).Locations) == 0 || mustDep(t, nunit).Locations[0].Position == nil || mustDep(t, nunit).Locations[0].Position.Line != 2 {
		t.Fatalf("NUnit locations = %#v, want packages.config line 2", mustDep(t, nunit).Locations)
	}
}

func TestNuGetPositionsRecordSelfClosingReferenceWithoutVersion(t *testing.T) {
	projectDir := t.TempDir()
	raw := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Central.Package" />
  </ItemGroup>
</Project>`)
	if err := os.WriteFile(filepath.Join(projectDir, "example.csproj"), raw, 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	positions := nugetPositions(projectDir)
	got := positions["central.package"]
	if len(got) != 1 || got[0].File != "example.csproj" || got[0].Line != 3 {
		t.Fatalf("central.package positions = %#v, want example.csproj line 3", got)
	}
	if got := positions["central.package@"]; len(got) != 0 {
		t.Fatalf("central.package@ positions = %#v, want none", got)
	}
}

func TestDepGraphFromDepsFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.deps.json")
	raw := []byte(`{
  "targets": {
    ".NETCoreApp,Version=v8.0": {
      "demo/1.0.0": {
        "dependencies": {
          "System.Runtime.Extensions": "4.3.0",
          "GSF.Core": "2.1.326-beta"
        }
      },
      "System.Runtime.Extensions/4.3.0": {},
      "GSF.Core/2.1.326-beta": {
        "dependencies": {
          "Antlr": "3.5.0.2",
          "FSharp.Core": "6.0.7"
        }
      },
      "Antlr/3.5.0.2": {},
      "FSharp.Core/6.0.7": {}
    }
  },
  "libraries": {
    "demo/1.0.0": {"type": "project"},
    "System.Runtime.Extensions/4.3.0": {"type": "package", "sha512": "sha512-runtimehash"},
    "GSF.Core/2.1.326-beta": {"type": "package"},
    "Antlr/3.5.0.2": {"type": "package"},
    "FSharp.Core/6.0.7": {"type": "package"}
  }
}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write deps file: %v", err)
	}

	g, err := depGraphFromDepsFiles([]string{path})
	if err != nil {
		t.Fatalf("depGraphFromDepsFiles() error = %v", err)
	}
	for _, want := range []string{"System.Runtime.Extensions@4.3.0", "GSF.Core@2.1.326-beta", "Antlr@3.5.0.2", "FSharp.Core@6.0.7"} {
		if _, ok := testnodes.Find(g, want); !ok {
			t.Fatalf("expected package %q, got %s", want, g.PrettyString())
		}
	}
	if _, ok := testnodes.Find(g, "demo@1.0.0"); ok {
		t.Fatalf("project package should not be included: %s", g.PrettyString())
	}
	deps, err := g.DirectDependencies(testnodes.ID(g, "GSF.Core@2.1.326-beta"))
	if err != nil {
		t.Fatalf("GSF.Core dependencies: %v", err)
	}
	for _, want := range []string{"Antlr@3.5.0.2", "FSharp.Core@6.0.7"} {
		found := false
		for _, dep := range deps {
			if testnodes.Is(dep, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected GSF.Core -> %s, got %#v", want, deps)
		}
	}
	runtime, ok := testnodes.Find(g, "System.Runtime.Extensions@4.3.0")
	if !ok {
		t.Fatal("expected System.Runtime.Extensions")
	}
	if string(mustDep(t, runtime).PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", string(mustDep(t, runtime).PrimaryScope()))
	}
}

func TestDetectorApplicableWithOnlyDepsJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example.deps.json"), []byte(`{"targets":{},"libraries":{}}`), 0o644); err != nil {
		t.Fatalf("write deps file: %v", err)
	}

	ok, err := (Detector{}).Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !ok {
		t.Fatal("expected NuGet detector to apply to .deps.json-only project")
	}
}

func TestNuGetProjectFilesFindsNestedProjects(t *testing.T) {
	projectDir := t.TempDir()
	nested := filepath.Join(projectDir, "src", "app")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	projectPath := filepath.Join(nested, "app.csproj")
	if err := os.WriteFile(projectPath, []byte(`<Project />`), 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}

	files, err := nugetProjectFiles(projectDir)
	if err != nil {
		t.Fatalf("nugetProjectFiles() error = %v", err)
	}
	if len(files) != 1 || files[0] != projectPath {
		t.Fatalf("files = %#v, want %q", files, projectPath)
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node sdk.GraphNode) *sdk.DependencyNode {
	t.Helper()
	dep, ok := node.(*sdk.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
