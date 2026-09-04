//go:build smoke

package smoke

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// SARIF is the format GitHub code scanning reads, and it is how Bomly Guard
// surfaces findings as inline annotations on a pull request -- so it is a
// user-visible contract with no smoke coverage at all until now. Nothing
// pinned the document's shape: which findings become results, how a rule is
// described, what location a finding points at, or that the driver still
// identifies itself.
//
// The finding comes from the package policy auditor with an explicit denied
// package, not from advisory data: the mock OSV server the audit cases share
// deliberately answers every query with no vulnerabilities, so a
// vulnerability-auditor run would pin an empty document and catch nothing. A
// denylist finding is fixed by the command line, so the rule, the result, and
// the location it points at are all stable.
func TestAuditScanSARIFGolden(t *testing.T) {
	requireTool(t, "go")
	srv := startMockOSV(t)

	sarifPath := filepath.Join(t.TempDir(), "out.sarif.json")
	_, stderr, code := runBomlyWithEnv(t, []string{"BOMLY_OSV_API_BASE=" + srv.URL},
		"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0",
		"--format", "json", "--enrich", "--audit",
		"--matchers", "osv", "--auditors", "package",
		"--detectors", "go",
		"--deny-package", "pkg:golang/golang.org/x/text@v0.3.5",
		"-o", "sarif="+sarifPath,
	)
	// A policy finding is a failed audit, so a non-zero exit is the expected
	// outcome here; exit 1 is "findings at or above the threshold".
	if code != 1 && code != 2 {
		t.Fatalf("bomly exited %d, want a findings exit\nstderr:\n%s", code, stderr)
	}

	raw, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read sarif output: %v", err)
	}
	assertGoldenDocument(t, "audit-sarif", normalizeSARIFDocument(t, raw))

	// The golden is only worth having if the document actually carries the
	// finding; an empty results array would pin nothing.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode sarif: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("sarif runs = %d, want one", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) == 0 || len(doc.Runs[0].Tool.Driver.Rules) == 0 {
		t.Fatalf("sarif carries %d results and %d rules; the denied package must appear as both",
			len(doc.Runs[0].Results), len(doc.Runs[0].Tool.Driver.Rules))
	}
}

// normalizeSARIFDocument blanks the values that track the release rather than
// the scan, then re-encodes so the golden is stable and readable.
func normalizeSARIFDocument(t *testing.T, raw []byte) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("normalizeSARIFDocument: unmarshal: %v\nraw:\n%s", err, string(raw))
	}
	normalizeSARIFDriverVersion(doc)
	normalizeSyntheticIDs(doc)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("normalizeSARIFDocument: marshal: %v", err)
	}
	return append(out, '\n')
}

// normalizeSARIFDriverVersion replaces the tool driver's version and its
// informational URI, which move with every release for reasons that say
// nothing about the document's findings.
func normalizeSARIFDriverVersion(node any) {
	switch v := node.(type) {
	case map[string]any:
		if _, isDriver := v["name"]; isDriver {
			if _, has := v["version"]; has {
				v["version"] = "<version>"
			}
			if _, has := v["semanticVersion"]; has {
				v["semanticVersion"] = "<version>"
			}
		}
		for _, val := range v {
			normalizeSARIFDriverVersion(val)
		}
	case []any:
		for _, child := range v {
			normalizeSARIFDriverVersion(child)
		}
	}
}
