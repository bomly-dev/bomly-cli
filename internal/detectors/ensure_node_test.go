package detectors_test

import (
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	first := sdk.NewDependencyRef("lodash", "4.17.21")
	surviving, err := detectors.EnsureNode(g, first)
	if err != nil || surviving != first {
		t.Fatalf("EnsureNode(new) = %v, %v; want the inserted node", surviving, err)
	}

	duplicate := sdk.NewDependencyRef("lodash", "4.17.21")
	surviving, err = detectors.EnsureNode(g, duplicate)
	if err != nil || surviving != first {
		t.Fatalf("EnsureNode(duplicate) = %v, %v; want the existing node", surviving, err)
	}

	if surviving, err := detectors.EnsureNode(nil, first); surviving != nil || err != nil {
		t.Fatalf("EnsureNode(nil graph) = %v, %v; want a no-op", surviving, err)
	}
	if surviving, err := detectors.EnsureNode(g, nil); surviving != nil || err != nil {
		t.Fatalf("EnsureNode(nil node) = %v, %v; want a no-op", surviving, err)
	}
}
