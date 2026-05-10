package qa_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/test/qa"
)

func TestLoadScanTargetsAndBuildArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	raw := []byte(`[
  {
    "name": "scan-npm",
    "url": "https://github.com/bomly-dev/example-javascript-npm",
    "ref": "v1.0.0",
    "args": ["--ecosystems", "npm"],
    "tools": ["npm"],
    "qa_enabled": true
  },
  {
    "name": "scan-reachability",
    "url": "https://github.com/bomly-dev/example-javascript-npm",
    "ref": "v1.0.0",
    "args": ["--enrich", "--reachability"]
  }
]`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write targets: %v", err)
	}

	targets, err := qa.LoadScanTargets(path)
	if err != nil {
		t.Fatalf("LoadScanTargets() error = %v", err)
	}
	if got := len(targets); got != 2 {
		t.Fatalf("expected 2 targets, got %d", got)
	}
	if got, want := targets[0].SmokeArgs(), []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "npm"}; !equalStrings(got, want) {
		t.Fatalf("SmokeArgs() = %#v, want %#v", got, want)
	}
	qaTargets := qa.QAScanTargets(targets)
	if len(qaTargets) != 1 || qaTargets[0].Name != "scan-npm" {
		t.Fatalf("unexpected QA targets: %#v", qaTargets)
	}
}

func TestLoadScanTargetsRejectsDuplicateNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	raw := []byte(`[
  {"name":"scan-go","url":"https://github.com/bomly-dev/example-go-gomod","ref":"v1.0.0"},
  {"name":"scan-go","url":"https://github.com/bomly-dev/example-go-gomod","ref":"v1.0.0"}
]`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write targets: %v", err)
	}
	if _, err := qa.LoadScanTargets(path); err == nil {
		t.Fatal("expected duplicate target error")
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
