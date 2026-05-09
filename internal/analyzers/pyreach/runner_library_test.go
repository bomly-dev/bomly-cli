package pyreach

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLibraryRunnerWalksProjectAndExtractsDistributions exercises the
// real in-process runner against a tiny on-disk fixture. It checks
// the end-to-end path: walk source → scan imports → map modules to
// PEP-503 distribution names → drop stdlib and venv content.
func TestLibraryRunnerWalksProjectAndExtractsDistributions(t *testing.T) {
	dir := t.TempDir()

	must := func(path string, body string) {
		t.Helper()
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	must("pyproject.toml", "[project]\nname = \"fixture\"\n")
	must("app.py", "import os\nimport requests\nimport yaml\nfrom flask import Flask\n")
	must("pkg/__init__.py", "from . import sub\n")
	must("pkg/sub.py", "import numpy as np\n")
	// Should be skipped: lives inside .venv/, so its imports must
	// not leak into the result.
	must(".venv/lib/python3.11/site-packages/django/__init__.py", "import django_internal\n")
	// Should be skipped: build artefact.
	must("build/lib/app.py", "import never_seen\n")

	r := NewRunner(nil)
	got, err := r.Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}

	wantPresent := []string{"requests", "pyyaml", "flask", "numpy"}
	for _, dist := range wantPresent {
		if _, ok := got.ImportedDistributions[dist]; !ok {
			t.Errorf("missing %q in imported set: %v", dist, got.ImportedDistributions)
		}
	}
	wantAbsent := []string{"os", "django_internal", "never_seen"}
	for _, dist := range wantAbsent {
		if _, ok := got.ImportedDistributions[dist]; ok {
			t.Errorf("unexpected %q in imported set", dist)
		}
	}
	if got.SourceFiles == 0 {
		t.Errorf("source files = 0; want > 0")
	}
}

func TestLibraryRunnerErrorsOnMissingDir(t *testing.T) {
	r := NewRunner(nil)
	_, err := r.Run(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing dir, got nil")
	}
}
