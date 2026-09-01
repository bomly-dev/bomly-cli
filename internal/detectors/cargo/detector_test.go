package cargo

import (
	"context"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{WorkingDir: "testdata/project"}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  sdk.PackageManagerCargo,
		Ecosystem:       sdk.EcosystemRust,
		ExecutionTarget: sdk.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := testnodes.FindDep(g, "bomly-cargo-smoke-helper@0.1.0")
	if !ok {
		t.Fatal("expected helper package")
	}
	if string(pkg.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", string(pkg.PrimaryScope()))
	}
}

func TestDepGraphFromMetadataWorkspace(t *testing.T) {
	raw := []byte(`{
  "packages": [
    {"id":"path+file:///demo#app@0.1.0","name":"app","version":"0.1.0","manifest_path":"/demo/Cargo.toml"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","name":"serde","version":"1.0.210","source":"registry+https://github.com/rust-lang/crates.io-index"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","name":"pretty_assertions","version":"1.4.1","source":"registry+https://github.com/rust-lang/crates.io-index"}
  ],
  "workspace_members": ["path+file:///demo#app@0.1.0"],
  "resolve": {
    "nodes": [
      {"id":"path+file:///demo#app@0.1.0","deps":[
        {"name":"serde","pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","dep_kinds":[{"kind":null,"target":null}]},
        {"name":"pretty_assertions","pkg":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","dep_kinds":[{"kind":"dev","target":null}]}
      ]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","deps":[]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","deps":[]}
    ]
  }
}`)
	g, err := depGraphFromMetadata(raw)
	if err != nil {
		t.Fatalf("depGraphFromMetadata() error = %v", err)
	}
	app, ok := testnodes.FindDep(g, "app@0.1.0")
	if !ok {
		t.Fatal("expected workspace package")
	}
	deps, err := g.DirectDependencies(app.NodeID())
	if err != nil {
		t.Fatalf("app dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two app dependencies, got %d", len(deps))
	}
	dev, ok := testnodes.FindDep(g, "pretty_assertions@1.4.1")
	if !ok {
		t.Fatal("expected dev package")
	}
	if string(dev.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev scope, got %q", string(dev.PrimaryScope()))
	}
	if !testnodes.Is(dev, "pkg:cargo/pretty_assertions@1.4.1") {
		t.Fatalf("unexpected purl %q", dev.NodeID())
	}
	if app.Source != sdk.DependencySourceProject {
		t.Fatalf("single project source = %q, want %q", app.Source, sdk.DependencySourceProject)
	}
	if dev.Source != sdk.DependencySourceRegistry {
		t.Fatalf("registry package source = %q, want %q", dev.Source, sdk.DependencySourceRegistry)
	}
}

func TestCargoDependencySource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   sdk.DependencySource
	}{
		{name: "registry", source: "registry+https://github.com/rust-lang/crates.io-index", want: sdk.DependencySourceRegistry},
		{name: "sparse registry", source: "sparse+https://index.crates.io/", want: sdk.DependencySourceRegistry},
		{name: "git", source: "git+https://github.com/example/helper?rev=abc#abc", want: sdk.DependencySourceGit},
		{name: "path", want: sdk.DependencySourceFile},
		{name: "unknown scheme", source: "custom+https://example.test", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cargoDependencySource(tt.source); got != tt.want {
				t.Fatalf("cargoDependencySource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestDepGraphFromMetadataWithScopeFilter(t *testing.T) {
	raw := []byte(`{
  "packages": [
    {"id":"path+file:///demo#app@0.1.0","name":"app","version":"0.1.0","manifest_path":"/demo/Cargo.toml"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","name":"serde","version":"1.0.210","source":"registry+https://github.com/rust-lang/crates.io-index"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","name":"pretty_assertions","version":"1.4.1","source":"registry+https://github.com/rust-lang/crates.io-index"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#diff@0.1.13","name":"diff","version":"0.1.13","source":"registry+https://github.com/rust-lang/crates.io-index"}
  ],
  "workspace_members": ["path+file:///demo#app@0.1.0"],
  "resolve": {
    "nodes": [
      {"id":"path+file:///demo#app@0.1.0","deps":[
        {"name":"serde","pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","dep_kinds":[{"kind":null,"target":null}]},
        {"name":"pretty_assertions","pkg":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","dep_kinds":[{"kind":"dev","target":null}]}
      ]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","deps":[]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#pretty_assertions@1.4.1","deps":[
        {"name":"diff","pkg":"registry+https://github.com/rust-lang/crates.io-index#diff@0.1.13","dep_kinds":[{"kind":null,"target":null}]}
      ]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#diff@0.1.13","deps":[]}
    ]
  }
}`)
	g, err := depGraphFromMetadataWithScope(raw, sdk.ScopeDevelopment)
	if err != nil {
		t.Fatalf("depGraphFromMetadataWithScope() error = %v", err)
	}
	if _, ok := testnodes.Find(g, "app@0.1.0"); !ok {
		t.Fatal("expected root package")
	}
	if _, ok := testnodes.Find(g, "pretty_assertions@1.4.1"); !ok {
		t.Fatalf("expected direct development package: %s", g.PrettyString())
	}
	if _, ok := testnodes.Find(g, "diff@0.1.13"); !ok {
		t.Fatalf("expected transitive development package: %s", g.PrettyString())
	}
	if _, ok := testnodes.Find(g, "serde@1.0.210"); ok {
		t.Fatalf("expected runtime package to be filtered: %s", g.PrettyString())
	}
}

func TestDepGraphFromLockFallback(t *testing.T) {
	lock := []byte(`# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "dev-helper",
 "helper",
]

[[package]]
name = "dev-helper"
version = "0.1.0"
source = "git+https://github.com/example/dev-helper?rev=abc#abc"

[[package]]
name = "helper"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	manifest := []byte(`[package]
name = "app"
version = "0.1.0"

[dependencies]
helper = { path = "helper" }

[dev-dependencies]
dev-helper = { path = "dev-helper" }
`)
	g, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := testnodes.Find(g, "app@0.1.0")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.DirectDependencies(root.NodeID())
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two root dependencies, got %d", len(deps))
	}
	dev, ok := testnodes.FindDep(g, "dev-helper@0.1.0")
	if !ok {
		t.Fatal("expected dev-helper package")
	}
	if string(dev.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", string(dev.PrimaryScope()))
	}
	if dev.Source != sdk.DependencySourceGit {
		t.Fatalf("dev-helper source = %q, want %q", dev.Source, sdk.DependencySourceGit)
	}
	helper, ok := testnodes.FindDep(g, "helper@0.1.0")
	if !ok {
		t.Fatal("expected helper package")
	}
	if helper.Source != sdk.DependencySourceRegistry {
		t.Fatalf("helper source = %q, want %q", helper.Source, sdk.DependencySourceRegistry)
	}
}

func TestDepGraphFromLockWithScopeFilter(t *testing.T) {
	lock := []byte(`# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "dev-helper",
 "helper",
]

[[package]]
name = "dev-helper"
version = "0.1.0"
dependencies = [
 "diff",
]

[[package]]
name = "diff"
version = "0.1.13"

[[package]]
name = "helper"
version = "0.1.0"
`)
	manifest := []byte(`[package]
name = "app"
version = "0.1.0"

[dependencies]
helper = { path = "helper" }

[dev-dependencies]
dev-helper = { path = "dev-helper" }
`)
	g, err := depGraphFromLockWithScope(lock, manifest, sdk.ScopeDevelopment)
	if err != nil {
		t.Fatalf("depGraphFromLockWithScope() error = %v", err)
	}
	if _, ok := testnodes.Find(g, "app@0.1.0"); !ok {
		t.Fatal("expected root package")
	}
	if _, ok := testnodes.Find(g, "dev-helper@0.1.0"); !ok {
		t.Fatalf("expected direct development package: %s", g.PrettyString())
	}
	if _, ok := testnodes.Find(g, "diff@0.1.13"); !ok {
		t.Fatalf("expected transitive development package: %s", g.PrettyString())
	}
	if _, ok := testnodes.Find(g, "helper@0.1.0"); ok {
		t.Fatalf("expected runtime package to be filtered: %s", g.PrettyString())
	}
}
