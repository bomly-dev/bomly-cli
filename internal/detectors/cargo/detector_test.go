package cargo

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
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
	pkg, ok := g.Node("bomly-cargo-smoke-helper@0.1.0")
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
	app, ok := g.Node("app@0.1.0")
	if !ok {
		t.Fatal("expected workspace package")
	}
	deps, err := g.DirectDependencies(app.ID)
	if err != nil {
		t.Fatalf("app dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two app dependencies, got %d", len(deps))
	}
	dev, ok := g.Node("pretty_assertions@1.4.1")
	if !ok {
		t.Fatal("expected dev package")
	}
	if string(dev.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected dev scope, got %q", string(dev.PrimaryScope()))
	}
	if dev.PURL != "pkg:cargo/pretty_assertions@1.4.1" {
		t.Fatalf("unexpected purl %q", dev.PURL)
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
	if _, ok := g.Node("app@0.1.0"); !ok {
		t.Fatal("expected root package")
	}
	if _, ok := g.Node("pretty_assertions@1.4.1"); !ok {
		t.Fatalf("expected direct development package: %s", g.PrettyString())
	}
	if _, ok := g.Node("diff@0.1.13"); !ok {
		t.Fatalf("expected transitive development package: %s", g.PrettyString())
	}
	if _, ok := g.Node("serde@1.0.210"); ok {
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
	g, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := g.Node("app@0.1.0")
	if !ok {
		t.Fatal("expected root package")
	}
	deps, err := g.DirectDependencies(root.ID)
	if err != nil {
		t.Fatalf("root dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected two root dependencies, got %d", len(deps))
	}
	dev, ok := g.Node("dev-helper@0.1.0")
	if !ok {
		t.Fatal("expected dev-helper package")
	}
	if string(dev.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", string(dev.PrimaryScope()))
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
	if _, ok := g.Node("app@0.1.0"); !ok {
		t.Fatal("expected root package")
	}
	if _, ok := g.Node("dev-helper@0.1.0"); !ok {
		t.Fatalf("expected direct development package: %s", g.PrettyString())
	}
	if _, ok := g.Node("diff@0.1.13"); !ok {
		t.Fatalf("expected transitive development package: %s", g.PrettyString())
	}
	if _, ok := g.Node("helper@0.1.0"); ok {
		t.Fatalf("expected runtime package to be filtered: %s", g.PrettyString())
	}
}
