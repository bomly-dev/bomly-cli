package cargo

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzDepGraphFromCargoLockWorkspace drives the workspace lock path end to
// end: the workspace manifest parsers (member patterns, [workspace.package]
// version inheritance), the member manifest parser, and the workspace graph
// builder — all of which consume untrusted repository files.
func FuzzDepGraphFromCargoLockWorkspace(f *testing.F) {
	f.Add(
		[]byte("[[package]]\nname = \"helper\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
		[]byte("[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"1.0.0\"\n"),
		[]byte("[package]\nname = \"helper\"\nversion.workspace = true\n\n[dependencies]\nserde = \"1\"\n"),
	)
	f.Add(
		[]byte("[[package]]\nname = \"helper\"\nversion = \"0.1.0\"\n"),
		[]byte("[workspace]\nmembers = [\"crates/helper\"]\n"),
		[]byte("[package]\nname = \"helper\"\nversion = { workspace = true }\n"),
	)
	f.Add([]byte("[[package]\n"), []byte("[workspace\nmembers = [\""), []byte("[package\nversion.works"))
	f.Fuzz(func(t *testing.T, lockRaw, rootRaw, memberRaw []byte) {
		if len(lockRaw)+len(rootRaw)+len(memberRaw) > testutil.MaxFuzzInputSize {
			return
		}
		parse := func() (*sdk.Graph, error) {
			workspaceVersion := parseCargoWorkspaceInheritedVersion(string(rootRaw))
			rootManifest := applyWorkspaceVersion(parseCargoManifest(string(rootRaw)), workspaceVersion)
			member := cargoLockMember{
				dir:      "crates/member",
				manifest: applyWorkspaceVersion(parseCargoManifest(string(memberRaw)), workspaceVersion),
			}
			graph, _, _, err := depGraphFromLockWorkspace(lockRaw, rootManifest, []cargoLockMember{member}, sdk.Scope(""))
			return graph, err
		}
		graph, err := parse()
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
		if _, again := parse(); (err == nil) != (again == nil) {
			t.Fatalf("parse determinism: first error = %v, second error = %v", err, again)
		}
		if first, second := parseCargoWorkspaceInheritedVersion(string(rootRaw)), parseCargoWorkspaceInheritedVersion(string(rootRaw)); first != second {
			t.Fatalf("workspace version determinism: %q then %q", first, second)
		}
		_ = parseCargoWorkspaceMembers(string(rootRaw))
	})
}

func FuzzDepGraphFromCargoLock(f *testing.F) {
	f.Add(
		[]byte("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"),
		[]byte("[package]\nname = \"fuzz-root\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"1\"\n"),
	)
	f.Add([]byte("[[package]\n"), []byte("[package\n"))
	f.Fuzz(func(t *testing.T, lockRaw, manifestRaw []byte) {
		if len(lockRaw)+len(manifestRaw) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromLockWithScope(lockRaw, manifestRaw, sdk.Scope(""))
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}
