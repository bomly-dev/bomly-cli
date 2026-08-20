package detectors_test

import (
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
		if filepath.Base(path) == "origin_fold.go" {
			return nil // the one place these rules are allowed to live
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

// Origin reconciliation must have one home, so the rule and its argument order
// are stated once. Writing it out by hand at a new fold site is how six of them
// accumulated, one review round at a time.
func TestOriginReconciliationGoesThroughFoldOrigin(t *testing.T) {
	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if strings.Contains(body, "ReconcileOrigin(") {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these files reconcile origin by hand; call detectors.FoldOrigin instead: %v", offenders)
	}
}

// The harder failure is a fold site that reconciles *nothing*: a hand-written
// "is it already there?" check that silently keeps the first node and drops the
// second record's origin. Twelve detectors had one, each written before origin
// existed. Adding a node has to go through the shared helper so a detector
// written later inherits the folding rather than having to know about it.
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
			"call detectors.AddNodeFolding instead: %v", offenders)
	}
}
