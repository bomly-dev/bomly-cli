package cargo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// A workspace member and an unrelated crate can share a name. Membership used
// to be resolved by name alone, so whichever lock record was read last won: the
// member took the external record's version and ResolvedURL, and the external
// crate vanished from the graph (issue #399). Both must keep their own
// identity: the member under its manifest's version with no external source,
// and the external crate as an ordinary dependency node.
func TestCargoLockWorkspaceMemberNameCollisionKeepsBothIdentities(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "consumer"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "helper 1.0.0 (git+https://github.com/external/helper?rev=main#aaaabbbbccccddddeeeeffff0000111122223333)",
]

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "consumer",
 "helper 0.1.0",
]

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/external/helper?rev=main#aaaabbbbccccddddeeeeffff0000111122223333"
`)
	root := cargoManifest{Name: "demo", Version: "0.1.0", Dependencies: []string{"consumer", "helper"}}
	members := []cargoLockMember{{dir: "crates/helper", manifest: cargoManifest{Name: "helper", Version: "0.1.0"}}}

	graph, modules, rootID, err := depGraphFromLockWorkspace(lock, root, members, sdk.Scope(""))
	if err != nil {
		t.Fatalf("depGraphFromLockWorkspace() error = %v", err)
	}

	member, ok := graph.Node("helper@0.1.0")
	if !ok {
		t.Fatalf("expected workspace member helper@0.1.0 in graph: %s", graph.PrettyString())
	}
	if member.Type != sdk.PackageTypeApplication {
		t.Fatalf("member type = %q, want application", member.Type)
	}
	if member.ResolvedURL != "" {
		t.Fatalf("member ResolvedURL = %q, want empty", member.ResolvedURL)
	}
	if origin := originOf(member); !origin.Empty() {
		t.Fatalf("member claims external origin %+v", origin)
	}
	if len(modules) != 1 || modules[0].rootID != member.ID {
		t.Fatalf("modules = %+v, want the member module rooted at %q", modules, member.ID)
	}

	external, ok := graph.Node("helper@1.0.0")
	if !ok {
		t.Fatalf("expected external helper@1.0.0 in graph: %s", graph.PrettyString())
	}
	if external.Type == sdk.PackageTypeApplication {
		t.Fatal("external crate must not be typed as an application")
	}
	if origin := originOf(external); origin.Repository != "https://github.com/external/helper" {
		t.Fatalf("external origin = %+v, want the external repository", origin)
	}

	// consumer resolved "helper 1.0.0 (git+...)": its edge must reach the
	// external crate, not the member.
	consumerDeps := directDependencyIDs(t, graph, "consumer@2.0.0")
	if !consumerDeps[external.ID] || consumerDeps[member.ID] {
		t.Fatalf("consumer dependencies = %v, want the external helper only", consumerDeps)
	}

	// demo resolved "helper 0.1.0": its direct helper edge is the member.
	rootDeps := directDependencyIDs(t, graph, rootID)
	if !rootDeps[member.ID] {
		t.Fatalf("root dependencies = %v, want the member helper", rootDeps)
	}
}

// Workspace version inheritance: a member manifest may declare no version at
// all. The member's lock record is still identifiable as the source-less
// record with its name, and a same-named external crate must not be mistaken
// for it.
func TestCargoLockWorkspaceMemberInheritedVersionResolvesOwnRecord(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/external/helper#aaaabbbbccccddddeeeeffff0000111122223333"
`)
	members := []cargoLockMember{{dir: "crates/helper", manifest: cargoManifest{Name: "helper"}}}

	graph, _, _, err := depGraphFromLockWorkspace(lock, cargoManifest{}, members, sdk.Scope(""))
	if err != nil {
		t.Fatalf("depGraphFromLockWorkspace() error = %v", err)
	}
	member, ok := graph.Node("helper@0.1.0")
	if !ok {
		t.Fatalf("expected member helper@0.1.0 (version from its lock record): %s", graph.PrettyString())
	}
	if member.Type != sdk.PackageTypeApplication || member.ResolvedURL != "" {
		t.Fatalf("member = %+v, want an application node with no external source", member)
	}
	if _, ok := graph.Node("helper@1.0.0"); !ok {
		t.Fatalf("expected external helper@1.0.0 to stay in the graph: %s", graph.PrettyString())
	}
}

// A member inheriting its version (`version.workspace = true`) must resolve
// the [workspace.package] version before lock-record matching: with the
// version known, a same-named source-less path dependency at another version
// cannot be claimed in its place.
func TestCargoLockWorkspaceInheritedVersionDisambiguatesSourcelessRecords(t *testing.T) {
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
	write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"1.0.0\"\n")
	write("crates/helper/Cargo.toml", "[package]\nname = \"helper\"\nversion.workspace = true\n")
	// The lockfile also holds a source-less path dependency named helper at
	// 0.1.0, declared before the member's own 1.0.0 record.
	write("Cargo.lock", `version = 3

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "helper"
version = "1.0.0"
`)

	result, err := Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: root})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	entries := result.Graphs.Entries
	if len(entries) != 1 {
		t.Fatalf("expected one member entry, got %d", len(entries))
	}
	graph := entries[0].Graph
	member, ok := graph.Node("helper@1.0.0")
	if !ok || member.Type != sdk.PackageTypeApplication {
		t.Fatalf("expected member helper@1.0.0 as an application node: %s", graph.PrettyString())
	}
}

// A member with no resolvable version and several same-named source-less lock
// records is genuinely ambiguous. No record may be claimed by file order --
// that could hand the member another path package's identity -- so the member
// keeps its manifest identity and every lock record stays in the graph.
func TestCargoLockWorkspaceAmbiguousSourcelessRecordsClaimNothing(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "helper"
version = "0.2.0"
`)
	members := []cargoLockMember{{dir: "crates/helper", manifest: cargoManifest{Name: "helper"}}}

	graph, modules, _, err := depGraphFromLockWorkspace(lock, cargoManifest{}, members, sdk.Scope(""))
	if err != nil {
		t.Fatalf("depGraphFromLockWorkspace() error = %v", err)
	}
	if len(modules) != 1 {
		t.Fatalf("modules = %+v, want one member", modules)
	}
	member, ok := graph.Node(modules[0].rootID)
	if !ok || member.Type != sdk.PackageTypeApplication || member.Version != "" {
		t.Fatalf("member = %+v, want an application node under its manifest identity", member)
	}
	for _, id := range []string{"helper@0.1.0", "helper@0.2.0"} {
		node, ok := graph.Node(id)
		if !ok {
			t.Fatalf("expected ambiguous record %q to stay in the graph: %s", id, graph.PrettyString())
		}
		if node.Type == sdk.PackageTypeApplication {
			t.Fatalf("ambiguous record %q must not be claimed as the member", id)
		}
	}
}

// A root-only workspace keeps [workspace.package] in the same manifest as its
// [package]; the single-package lock path must resolve `version.workspace =
// true` from it so the application node and PURL carry the real version.
func TestCargoLockRootOnlyWorkspaceInheritsVersion(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "1.2.3"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	manifest := []byte(`[workspace]

[workspace.package]
version = "1.2.3"

[package]
name = "app"
version.workspace = true

[dependencies]
serde = "1"
`)

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := graph.Node("app@1.2.3")
	if !ok || !root.FirstParty {
		t.Fatalf("expected first-party root app@1.2.3: %s", graph.PrettyString())
	}
	if root.Version != "1.2.3" {
		t.Fatalf("root version = %q, want the inherited 1.2.3", root.Version)
	}
	rootDeps := directDependencyIDs(t, graph, root.ID)
	if !rootDeps["serde@1.0.210"] {
		t.Fatalf("root dependencies = %v, want serde@1.0.210", rootDeps)
	}
}

// parseCargoManifest recognizes both spellings of workspace version
// inheritance and never records the inline table as a literal version.
func TestParseCargoManifestWorkspaceVersionInheritance(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{"dotted key", "[package]\nname = \"helper\"\nversion.workspace = true\n"},
		{"inline table", "[package]\nname = \"helper\"\nversion = { workspace = true }\n"},
		{"dotted key with inline comment", "[package]\nname = \"helper\"\nversion.workspace = true # inherited\n"},
		{"section table", "[package]\nname = \"helper\"\n\n[package.version]\nworkspace = true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := parseCargoManifest(tc.toml)
			if !manifest.VersionInherited {
				t.Fatal("expected VersionInherited to be set")
			}
			if manifest.Version != "" {
				t.Fatalf("Version = %q, want empty until the workspace version is applied", manifest.Version)
			}
		})
	}
	roots := []struct {
		name string
		toml string
	}{
		{"section table", "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"2.5.0\"\n"},
		{"dotted key", "[workspace]\nmembers = [\"crates/*\"]\npackage.version = \"2.5.0\"\n"},
		{"inline comment after the value", "[workspace]\n\n[workspace.package]\nversion = \"2.5.0\" # release train\n"},
		{"literal string", "[workspace]\n\n[workspace.package]\nversion = '2.5.0'\n"},
		{"inline table", "[workspace]\npackage = { version = \"2.5.0\" }\n"},
		{"inline table with sibling keys", "[workspace]\npackage = { edition = \"2021\", version = \"2.5.0\", rust-version = \"1.70\" }\n"},
	}
	for _, tc := range roots {
		if version := parseCargoWorkspaceInheritedVersion(tc.toml); version != "2.5.0" {
			t.Fatalf("parseCargoWorkspaceInheritedVersion(%s) = %q, want 2.5.0", tc.name, version)
		}
	}
	// The same decoding applies to ordinary manifest values.
	commented := parseCargoManifest("[package]\nname = \"helper\" # crate\nversion = \"1.2.3\" # release\n")
	if commented.Name != "helper" || commented.Version != "1.2.3" {
		t.Fatalf("manifest with inline comments = %+v, want name helper version 1.2.3", commented)
	}
}

// The cargo metadata path keys everything by cargo's source-qualified package
// IDs; a member and a same-named external crate at different versions must
// both survive with their own identity there too.
func TestCargoMetadataWorkspaceMemberNameCollisionKeepsBothIdentities(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "path+file:///w/crates/helper#helper@0.1.0", "name": "helper", "version": "0.1.0", "source": null, "manifest_path": "/w/crates/helper/Cargo.toml"},
        {"id": "path+file:///w#demo@0.1.0", "name": "demo", "version": "0.1.0", "source": null, "manifest_path": "/w/Cargo.toml"},
        {"id": "git+https://github.com/external/helper?rev=main#helper@1.0.0", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/external/helper?rev=main#aaaabbbbccccddddeeeeffff0000111122223333"},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#consumer@2.0.0", "name": "consumer", "version": "2.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"}
      ],
      "workspace_members": ["path+file:///w#demo@0.1.0", "path+file:///w/crates/helper#helper@0.1.0"],
      "resolve": {"nodes": [
        {"id": "path+file:///w#demo@0.1.0", "deps": [
          {"name": "consumer", "pkg": "registry+https://github.com/rust-lang/crates.io-index#consumer@2.0.0", "dep_kinds": [{"kind": null, "target": null}]},
          {"name": "helper", "pkg": "path+file:///w/crates/helper#helper@0.1.0", "dep_kinds": [{"kind": null, "target": null}]}
        ]},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#consumer@2.0.0", "deps": [
          {"name": "helper", "pkg": "git+https://github.com/external/helper?rev=main#helper@1.0.0", "dep_kinds": [{"kind": null, "target": null}]}
        ]}
      ]}
    }`)

	graph, err := depGraphFromMetadata(metadata)
	if err != nil {
		t.Fatalf("depGraphFromMetadata() error = %v", err)
	}
	member, ok := graph.Node("helper@0.1.0")
	if !ok {
		t.Fatalf("expected member helper@0.1.0: %s", graph.PrettyString())
	}
	if member.Type != sdk.PackageTypeApplication || member.ResolvedURL != "" {
		t.Fatalf("member = %+v, want an application node with no external source", member)
	}
	external, ok := graph.Node("helper@1.0.0")
	if !ok {
		t.Fatalf("expected external helper@1.0.0: %s", graph.PrettyString())
	}
	if origin := originOf(external); origin.Repository != "https://github.com/external/helper" {
		t.Fatalf("external origin = %+v, want the external repository", origin)
	}
	consumerDeps := directDependencyIDs(t, graph, "consumer@2.0.0")
	if !consumerDeps[external.ID] || consumerDeps[member.ID] {
		t.Fatalf("consumer dependencies = %v, want the external helper only", consumerDeps)
	}
}

// When the collision is exact -- one name@version resolved both as a workspace
// member and from a git remote -- the member keeps the plain node ID and the
// external record becomes the qualified occurrence, never the other way
// around: first-party code does not surrender its identity to sort order.
func TestCargoMetadataWorkspaceMemberKeepsPlainIDOnExactCollision(t *testing.T) {
	metadata := []byte(`{
      "packages": [
        {"id": "path+file:///w/crates/helper#helper@1.0.0", "name": "helper", "version": "1.0.0", "source": null, "manifest_path": "/w/crates/helper/Cargo.toml"},
        {"id": "path+file:///w#demo@0.1.0", "name": "demo", "version": "0.1.0", "source": null, "manifest_path": "/w/Cargo.toml"},
        {"id": "git+https://github.com/external/helper#helper@1.0.0", "name": "helper", "version": "1.0.0", "source": "git+https://github.com/external/helper#aaaabbbbccccddddeeeeffff0000111122223333"}
      ],
      "workspace_members": ["path+file:///w#demo@0.1.0", "path+file:///w/crates/helper#helper@1.0.0"],
      "resolve": {"nodes": []}
    }`)

	graph, err := depGraphFromMetadata(metadata)
	if err != nil {
		t.Fatalf("depGraphFromMetadata() error = %v", err)
	}
	member, ok := graph.Node("helper@1.0.0")
	if !ok {
		t.Fatalf("expected plain helper@1.0.0 node: %s", graph.PrettyString())
	}
	if member.Type != sdk.PackageTypeApplication {
		t.Fatalf("helper@1.0.0 type = %q, want the workspace member under the plain ID", member.Type)
	}
	if origin := originOf(member); !origin.Empty() {
		t.Fatalf("member claims external origin %+v", origin)
	}
	var externals int
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "helper" && dep.ID != member.ID {
			externals++
			if origin := originOf(dep); origin.Repository != "https://github.com/external/helper" {
				t.Fatalf("external occurrence origin = %+v, want the external repository", origin)
			}
		}
		return true
	})
	if externals != 1 {
		t.Fatalf("external helper occurrences = %d, want 1", externals)
	}
}

// The single-package lock path has the same collision: a crate that merely
// shares the root package's name must not be dropped from the graph.
func TestCargoLockRootNameCollisionKeepsExternalCrate(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "consumer",
]

[[package]]
name = "app"
version = "2.0.0"
source = "git+https://github.com/external/app#aaaabbbbccccddddeeeeffff0000111122223333"

[[package]]
name = "consumer"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "app 2.0.0 (git+https://github.com/external/app#aaaabbbbccccddddeeeeffff0000111122223333)",
]
`)
	manifest := []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nconsumer = \"2\"\n")

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	root, ok := graph.Node("app@0.1.0")
	if !ok || !root.FirstParty {
		t.Fatalf("expected first-party root app@0.1.0: %s", graph.PrettyString())
	}
	if origin := originOf(root); !origin.Empty() {
		t.Fatalf("root claims external origin %+v", origin)
	}
	external, ok := graph.Node("app@2.0.0")
	if !ok {
		t.Fatalf("expected external app@2.0.0 to stay in the graph: %s", graph.PrettyString())
	}
	consumerDeps := directDependencyIDs(t, graph, "consumer@2.0.0")
	if !consumerDeps[external.ID] || consumerDeps[root.ID] {
		t.Fatalf("consumer dependencies = %v, want the external app only", consumerDeps)
	}
}

// Cargo.lock writes version-qualified dependency references whenever two
// records share a name. Those references must resolve to the exact record,
// not to whichever same-named record appears first in the file.
func TestCargoLockVersionQualifiedDependencyRefsResolveExactly(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "left",
 "right",
]

[[package]]
name = "helper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "helper"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "left"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "helper 1.0.0",
]

[[package]]
name = "right"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "helper 2.0.0",
]
`)
	manifest := []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nleft = \"1\"\nright = \"1\"\n")

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	leftDeps := directDependencyIDs(t, graph, "left@1.0.0")
	if !leftDeps["helper@1.0.0"] || leftDeps["helper@2.0.0"] {
		t.Fatalf("left dependencies = %v, want helper@1.0.0 only", leftDeps)
	}
	rightDeps := directDependencyIDs(t, graph, "right@1.0.0")
	if !rightDeps["helper@2.0.0"] || rightDeps["helper@1.0.0"] {
		t.Fatalf("right dependencies = %v, want helper@2.0.0 only", rightDeps)
	}
}

// Cargo qualifies a dependency reference with the source identity only:
// records pin the resolved commit ("git+URL#sha"), references omit it
// ("name version (git+URL)"). Such references must still resolve to the
// exact occurrence, or the edge to a git crate silently disappears whenever
// two same-named same-versioned records force source qualification.
func TestCargoLockGitRefsWithoutPreciseFragmentResolve(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "consumer",
]

[[package]]
name = "consumer"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "helper 1.0.0 (git+https://github.com/b/helper)",
]

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/a/helper#aaaabbbbccccddddeeeeffff0000111122223333"

[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://github.com/b/helper#bbbbccccddddeeeeffff00001111222233334444"
`)
	manifest := []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nconsumer = \"2\"\n")

	graph, err := depGraphFromLock(lock, manifest)
	if err != nil {
		t.Fatalf("depGraphFromLock() error = %v", err)
	}
	consumerDeps := directDependencyIDs(t, graph, "consumer@2.0.0")
	if len(consumerDeps) != 1 {
		t.Fatalf("consumer dependencies = %v, want exactly the b-remote helper occurrence", consumerDeps)
	}
	for id := range consumerDeps {
		child, ok := graph.Node(id)
		if !ok {
			t.Fatalf("consumer dependency %q missing from graph", id)
		}
		if origin := originOf(child); origin.Repository != "https://github.com/b/helper" {
			t.Fatalf("consumer edge reached %q with origin %+v, want the b-remote occurrence", id, origin)
		}
	}
}

// directDependencyIDs returns the IDs a node points at, as a set.
func directDependencyIDs(t *testing.T, g *sdk.Graph, nodeID string) map[string]bool {
	t.Helper()
	deps, err := g.DirectDependencies(nodeID)
	if err != nil {
		t.Fatalf("dependencies of %q: %v", nodeID, err)
	}
	out := make(map[string]bool, len(deps))
	for _, dep := range deps {
		if dep != nil {
			out[dep.ID] = true
		}
	}
	return out
}
