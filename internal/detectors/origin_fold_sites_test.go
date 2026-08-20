package detectors_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Origin reconciliation is easy to get wrong by writing it out by hand at a new
// fold site -- that is how six of them accumulated one review at a time. Every
// caller must go through FoldOrigin, so the rule and its argument order live in
// one place. This fails if a hand-written reconciliation reappears.
func TestOriginReconciliationGoesThroughFoldOrigin(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == "origin_fold.go" {
			return nil // the one place the rule is allowed to live
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "ReconcileOrigin(") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("these files reconcile origin by hand; call detectors.FoldOrigin instead: %v", offenders)
	}
}
