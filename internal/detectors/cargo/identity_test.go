package cargo

import (
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
