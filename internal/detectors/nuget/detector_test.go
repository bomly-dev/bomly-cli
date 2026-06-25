package nuget

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
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
	pkg, ok := g.Node("Newtonsoft.Json@13.0.3")
	if !ok {
		t.Fatal("expected Newtonsoft.Json package")
	}
	if pkg.PURL != "pkg:nuget/Newtonsoft.Json@13.0.3" {
		t.Fatalf("unexpected purl %q", pkg.PURL)
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
	root, ok := g.Node("root")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.DirectDependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "Newtonsoft.Json" {
		t.Fatalf("expected root to depend on Newtonsoft.Json, got %#v", deps)
	}
	systemText, ok := g.Node("System.Text.Json@8.0.0")
	if !ok {
		t.Fatal("expected System.Text.Json package")
	}
	if string(systemText.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected transitive runtime scope, got %q", string(systemText.PrimaryScope()))
	}
}

func TestDepGraphFromPackagesConfig(t *testing.T) {
	raw := []byte(`<packages><package id="NUnit" version="4.2.2" targetFramework="net48" /></packages>`)
	g, err := depGraphFromPackagesConfig(raw)
	if err != nil {
		t.Fatalf("depGraphFromPackagesConfig() error = %v", err)
	}
	pkg, ok := g.Node("NUnit@4.2.2")
	if !ok {
		t.Fatal("expected NUnit package")
	}
	if pkg.PURL != "pkg:nuget/NUnit@4.2.2" {
		t.Fatalf("unexpected purl %q", pkg.PURL)
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
		pkg, ok := g.Node(want)
		if !ok {
			t.Fatalf("expected package %q", want)
		}
		if string(pkg.PrimaryScope()) != string(sdk.ScopeRuntime) {
			t.Fatalf("expected runtime scope for %q, got %q", want, string(pkg.PrimaryScope()))
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
	systemRuntime, ok := g.Node("System.Runtime.Extensions@4.3.0")
	if !ok || len(systemRuntime.Locations) == 0 || systemRuntime.Locations[0].Position == nil || systemRuntime.Locations[0].Position.Line != 3 {
		t.Fatalf("System.Runtime.Extensions locations = %#v, want inline PackageReference line 3", systemRuntime.Locations)
	}
	newtonsoft, ok := g.Node("Newtonsoft.Json@13.0.3")
	if !ok || len(newtonsoft.Locations) == 0 || newtonsoft.Locations[0].Position == nil || newtonsoft.Locations[0].Position.Line != 5 {
		t.Fatalf("Newtonsoft.Json locations = %#v, want Version element line 5", newtonsoft.Locations)
	}
	if newtonsoft.Locations[0].RealPath != "src/app/example.csproj" {
		t.Fatalf("Newtonsoft.Json location path = %#v, want nested project path", newtonsoft.Locations[0])
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
	nunit, ok := g.Node("NUnit@4.2.2")
	if !ok || len(nunit.Locations) == 0 || nunit.Locations[0].Position == nil || nunit.Locations[0].Position.Line != 2 {
		t.Fatalf("NUnit locations = %#v, want packages.config line 2", nunit.Locations)
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
		if _, ok := g.Node(want); !ok {
			t.Fatalf("expected package %q, got %s", want, g.PrettyString())
		}
	}
	if _, ok := g.Node("demo@1.0.0"); ok {
		t.Fatalf("project package should not be included: %s", g.PrettyString())
	}
	deps, err := g.DirectDependencies("GSF.Core@2.1.326-beta")
	if err != nil {
		t.Fatalf("GSF.Core dependencies: %v", err)
	}
	gotDeps := make(map[string]struct{}, len(deps))
	for _, dep := range deps {
		gotDeps[dep.ID] = struct{}{}
	}
	for _, want := range []string{"Antlr@3.5.0.2", "FSharp.Core@6.0.7"} {
		if _, ok := gotDeps[want]; !ok {
			t.Fatalf("expected GSF.Core -> %s, got %#v", want, deps)
		}
	}
	runtime, ok := g.Node("System.Runtime.Extensions@4.3.0")
	if !ok {
		t.Fatal("expected System.Runtime.Extensions")
	}
	if string(runtime.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", string(runtime.PrimaryScope()))
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
