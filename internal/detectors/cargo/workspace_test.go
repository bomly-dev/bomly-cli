package cargo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestParseCargoWorkspaceMembers(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want []string
	}{
		{"inline", "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n", []string{"crates/a", "crates/b"}},
		{"multiline", "[workspace]\nmembers = [\n  \"crates/a\",\n  \"crates/b\",\n]\n", []string{"crates/a", "crates/b"}},
		{"glob", "[workspace]\nmembers = [\"crates/*\"]\n", []string{"crates/*"}},
		{"no workspace", "[package]\nname = \"app\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCargoWorkspaceMembers(tc.toml)
			if len(got) != len(tc.want) {
				t.Fatalf("parseCargoWorkspaceMembers() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseCargoWorkspaceMembers() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestDetectionResultFromMetadataWorkspacePerModuleEntries(t *testing.T) {
	raw := []byte(`{
  "packages": [
    {"id":"path+file:///demo/crates/a#a@0.1.0","name":"a","version":"0.1.0","manifest_path":"/demo/crates/a/Cargo.toml"},
    {"id":"path+file:///demo/crates/b#b@0.2.0","name":"b","version":"0.2.0","manifest_path":"/demo/crates/b/Cargo.toml"},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","name":"serde","version":"1.0.210","source":"registry"}
  ],
  "workspace_members": ["path+file:///demo/crates/a#a@0.1.0", "path+file:///demo/crates/b#b@0.2.0"],
  "resolve": {
    "nodes": [
      {"id":"path+file:///demo/crates/a#a@0.1.0","deps":[
        {"name":"serde","pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","dep_kinds":[{"kind":null,"target":null}]},
        {"name":"b","pkg":"path+file:///demo/crates/b#b@0.2.0","dep_kinds":[{"kind":null,"target":null}]}
      ]},
      {"id":"path+file:///demo/crates/b#b@0.2.0","deps":[
        {"name":"serde","pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","dep_kinds":[{"kind":null,"target":null}]}
      ]},
      {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.210","deps":[]}
    ]
  }
}`)
	result, err := Detector{}.detectionResultFromMetadata(sdk.DetectionRequest{ProjectPath: "/demo"}, raw)
	if err != nil {
		t.Fatalf("detectionResultFromMetadata() error = %v", err)
	}
	entries := result.Graphs.Entries
	if len(entries) != 2 {
		t.Fatalf("expected one entry per member, got %d", len(entries))
	}
	byPath := map[string]sdk.GraphEntry{}
	for _, entry := range entries {
		byPath[entry.Manifest.Path] = entry
	}
	a, ok := byPath["crates/a/Cargo.toml"]
	if !ok {
		t.Fatalf("expected crates/a/Cargo.toml entry, got %v", byPath)
	}
	if _, ok := byPath["crates/b/Cargo.toml"]; !ok {
		t.Fatalf("expected crates/b/Cargo.toml entry, got %v", byPath)
	}
	// Member a reaches its inter-member dep b and the shared serde;
	// the synthesized virtual workspace root never appears in entries.
	for _, want := range []string{"a@0.1.0", "b@0.2.0", "serde@1.0.210"} {
		if _, ok := a.Graph.Node(want); !ok {
			t.Fatalf("expected %q in member a graph", want)
		}
	}
	if _, ok := a.Graph.Node("root"); ok {
		t.Fatal("virtual workspace root must not leak into member entries")
	}
}

func TestResolveFromLockVirtualWorkspaceEmitsMemberEntries(t *testing.T) {
	original := cargoExecLookPath
	cargoExecLookPath = func(string) (string, error) { return "", errors.New("cargo unavailable") }
	t.Cleanup(func() { cargoExecLookPath = original })

	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n")
	write("crates/a/Cargo.toml", "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nb = { path = \"../b\" }\n")
	write("crates/b/Cargo.toml", "[package]\nname = \"b\"\nversion = \"0.2.0\"\n\n[dependencies]\nserde = \"1\"\n\n[dev-dependencies]\npretty_assertions = \"1\"\n")
	write("Cargo.lock", `version = 3

[[package]]
name = "a"
version = "0.1.0"
dependencies = [
 "b",
 "serde",
]

[[package]]
name = "b"
version = "0.2.0"
dependencies = [
 "pretty_assertions",
 "serde",
]

[[package]]
name = "pretty_assertions"
version = "1.4.1"

[[package]]
name = "serde"
version = "1.0.210"
`)

	result, err := Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: root})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	entries := result.Graphs.Entries
	if len(entries) != 2 {
		t.Fatalf("expected one entry per member for a virtual workspace, got %d", len(entries))
	}
	byPath := map[string]sdk.GraphEntry{}
	for _, entry := range entries {
		byPath[entry.Manifest.Path] = entry
	}
	a, ok := byPath["crates/a/Cargo.toml"]
	if !ok {
		t.Fatalf("expected crates/a/Cargo.toml entry, got %v", byPath)
	}
	b, ok := byPath["crates/b/Cargo.toml"]
	if !ok {
		t.Fatalf("expected crates/b/Cargo.toml entry, got %v", byPath)
	}
	for _, want := range []string{"a@0.1.0", "b@0.2.0", "serde@1.0.210"} {
		if _, ok := a.Graph.Node(want); !ok {
			t.Fatalf("expected %q in member a graph", want)
		}
	}
	if _, ok := b.Graph.Node("a@0.1.0"); ok {
		t.Fatal("member b graph must not contain member a")
	}
	dev, ok := b.Graph.Node("pretty_assertions@1.4.1")
	if !ok {
		t.Fatal("expected member dev dependency in member b graph")
	}
	hasDev := false
	for _, scope := range dev.Scopes {
		if scope == sdk.ScopeDevelopment {
			hasDev = true
		}
	}
	if !hasDev {
		t.Fatalf("expected development scope on member dev dependency, got %v", dev.Scopes)
	}
}

func TestResolveFromLockSinglePackageStillSingleEntry(t *testing.T) {
	original := cargoExecLookPath
	cargoExecLookPath = func(string) (string, error) { return "", errors.New("cargo unavailable") }
	t.Cleanup(func() { cargoExecLookPath = original })

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Cargo.lock"), []byte("version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}
	result, err := Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: root})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected single entry for single-package project, got %d", len(result.Graphs.Entries))
	}
}
