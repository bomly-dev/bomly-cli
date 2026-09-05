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
//
// The helper is detectorkit.EnsureNode in the SDK now; nothing under internal/
// is exempt, because there is no longer a local copy for a detector to reach
// for instead.
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
			"call detectorkit.EnsureNode instead: %v", offenders)
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

// The SPDX expression parser panics on some malformed input, and license
// strings arrive from lockfiles and registry APIs that a repository controls,
// so no package here may call it directly.
//
// The guard used to live in internal/licenseexpr, which wrapped the parser and
// caught its panics. That package is gone: bomly-sdk/spdxkit owns expression
// handling now, panic guard included, so the rule is no longer "route through
// the local wrapper" but "do not import the parser at all". Written as a
// module-path check rather than an import-list scan of one package, because
// the point is that nothing under internal/ reaches the parser by any route.
func TestNoDirectSPDXExpressionUse(t *testing.T) {
	const spdxModule = "github.com/github/go-spdx"

	// This file names the module in the rule it enforces, so it is the one
	// exemption -- the same shape the guard had when it lived beside the
	// wrapper it policed.
	self := "guards_test.go"

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if strings.Contains(body, spdxModule) {
			offenders = append(offenders, path)
		}
	})
	// Test files too: a test reaching the parser directly proves the same
	// crash is reachable, and it is where the temptation lives.
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, "_test.go") || filepath.Base(path) == self {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), spdxModule) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("these files reference %s directly; the parser panics on malformed input, "+
			"so go through bomly-sdk/spdxkit instead: %v", spdxModule, offenders)
	}
}
