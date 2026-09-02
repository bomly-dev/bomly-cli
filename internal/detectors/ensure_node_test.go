package detectors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// internalRoot is the tree these guards police.
const internalRoot = "../../internal"

// walkInternalGo visits every non-test Go file under internal/.
func walkInternalGo(t *testing.T, visit func(path, body string)) {
	t.Helper()
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == "ensure_node.go" {
			return nil // the one place node insertion is allowed to live
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		visit(path, string(body))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// A hand-written "is it already there?" check before an insert is how a dozen
// detectors independently decided what happens to a duplicate record. Node
// insertion goes through the shared helper so the behavior is decided once and
// a detector written later inherits it.
func TestNodeInsertionGoesThroughTheSharedHelper(t *testing.T) {
	// A lookup on the graph followed by an insert, which is the shape that
	// silently discards the duplicate.
	lookupThenAdd := regexp.MustCompile(`(?s)\.Node\(node\.ID\).{0,200}?\.AddNode\(`)

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if lookupThenAdd.MatchString(body) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these files check for an existing node and insert by hand, which drops the duplicate's origin; "+
			"call detectors.EnsureNode instead: %v", offenders)
	}
}

// Raw manifest values -- local paths, credentialed private-registry URLs --
// must be unreachable from the export layer. Export reads Origin.Normalized(),
// which is validated end to end; ResolvedURL is evidence, never output. This
// is the structural answer to "could export accidentally leak the raw value":
// it cannot name it.
func TestExportNeverReadsResolvedURL(t *testing.T) {
	root := filepath.Join(internalRoot, "sbom")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var offenders []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), "ResolvedURL") {
			offenders = append(offenders, path)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("the export layer references ResolvedURL; it must read Origin.Normalized() only: %v", offenders)
	}
}

func TestEnsureNode(t *testing.T) {
	g := sdk.New()
	first := testnodes.Ref("lodash", "4.17.21")
	surviving, err := detectors.EnsureNode(g, first)
	if err != nil || surviving != first {
		t.Fatalf("EnsureNode(new) = %v, %v; want the inserted node", surviving, err)
	}

	duplicate := testnodes.Ref("lodash", "4.17.21")
	surviving, err = detectors.EnsureNode(g, duplicate)
	if err != nil || surviving != first {
		t.Fatalf("EnsureNode(duplicate) = %v, %v; want the existing node", surviving, err)
	}

	if surviving, err := detectors.EnsureNode(nil, first); surviving != nil || err != nil {
		t.Fatalf("EnsureNode(nil graph) = %v, %v; want a no-op", surviving, err)
	}
	if surviving, err := detectors.EnsureNode(g, (*sdk.DependencyNode)(nil)); surviving != nil || err != nil {
		t.Fatalf("EnsureNode(nil node) = %v, %v; want a no-op", surviving, err)
	}
}

func scopedDependency(scope sdk.Scope, resolvedURL string) *sdk.DependencyNode {
	return testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
		Name:    "requests",
		Version: "2.31.0"}, ResolvedURL: resolvedURL, Scopes: sdk.ScopesOf(scope),
	})
}

// One package listed in two dependency groups is reachable at both scopes.
// The fold is where the second group's record disappears, so the fold is
// where its scope must survive.
func TestEnsureNodeUnionsScopesOnFold(t *testing.T) {
	g := sdk.New()
	runtime := scopedDependency(sdk.ScopeRuntime, "")
	if _, err := detectors.EnsureNode(g, runtime); err != nil {
		t.Fatalf("EnsureNode(runtime) error = %v", err)
	}

	surviving, err := detectors.EnsureNode(g, scopedDependency(sdk.ScopeDevelopment, ""))
	if err != nil || surviving != runtime {
		t.Fatalf("EnsureNode(duplicate) = %v, %v; want the existing node", surviving, err)
	}
	if !surviving.HasScope(sdk.ScopeRuntime) || !surviving.HasScope(sdk.ScopeDevelopment) {
		t.Fatalf("surviving scopes = %v; want the union of both records' scopes", surviving.Scopes)
	}
}

// Two records that resolved one identity from different places fold into one
// node. The occurrence machinery used to keep them apart; ADR-0041 keeps the
// disagreement on a single identity instead, as two origins, which is the
// dependency-confusion signal the split nodes were standing in for.
func TestEnsureNodeFoldsRecordsThatResolvedFromDifferentPlaces(t *testing.T) {
	g := sdk.New()
	first := scopedDependency(sdk.ScopeRuntime, "https://a.example/requests-2.31.0.tar.gz")
	first.Origins = sdk.MergeOrigins(nil, originsFor("https://a.example/requests-2.31.0.tar.gz"))
	if _, err := detectors.EnsureNode(g, first); err != nil {
		t.Fatalf("EnsureNode(first) error = %v", err)
	}

	other := scopedDependency(sdk.ScopeDevelopment, "https://b.example/requests-2.31.0.tar.gz")
	other.Origins = sdk.MergeOrigins(nil, originsFor("https://b.example/requests-2.31.0.tar.gz"))
	surviving, err := detectors.EnsureNode(g, other)
	if err != nil || surviving != first {
		t.Fatalf("EnsureNode(other resolution) = %v, %v; want a fold into the one identity", surviving, err)
	}
	if g.Size() != 1 {
		t.Fatalf("graph size = %d; want one node per identity", g.Size())
	}
	if !surviving.HasScope(sdk.ScopeRuntime) || !surviving.HasScope(sdk.ScopeDevelopment) {
		t.Fatalf("surviving scopes = %v; want the union of both records", surviving.Scopes)
	}
	if len(surviving.Origins) != 2 {
		t.Fatalf("surviving origins = %v; want both resolutions kept on the folded node", surviving.Origins)
	}
}

// originsFor builds the origin list an artifact URL asserts, or nothing when
// the URL is not one the publication gates accept.
func originsFor(artifactURL string) []sdk.DependencyOrigin {
	origin := sdk.ArtifactOrigin(artifactURL)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}
