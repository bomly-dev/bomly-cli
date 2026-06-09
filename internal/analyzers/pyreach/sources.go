package pyreach

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// projectFileMarkers names every file whose presence at a directory
// makes that directory a Python project root. The list is the union
// of the manifests recognized by Bomly's Python detectors (pip,
// pipenv, poetry, uv, pdm, setuppy) plus the most common loose
// requirements layouts.
var projectFileMarkers = []string{
	"pyproject.toml",
	"setup.py",
	"setup.cfg",
	"Pipfile",
	"Pipfile.lock",
	"poetry.lock",
	"pdm.lock",
	"uv.lock",
	"requirements.txt",
	"requirements-dev.txt",
}

// hasProjectMarker returns true when dir contains any of the recognized
// Python project files. Used to filter out source-only subdirectories
// when walking up from a package location.
func hasProjectMarker(dir string) bool {
	for _, name := range projectFileMarkers {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	// Also accept any requirements*.txt variant (requirements-prod.txt,
	// requirements/base.txt etc. — the latter lives in a subdir, so we
	// only catch top-level variants here).
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
			return true
		}
	}
	return false
}

// walkSourceFiles invokes fn for every .py file under root, skipping
// directories whose names appear in skipDirs. Returns the list of
// directory names actually skipped (for telemetry) and any walk error.
//
// The walker stops on context cancellation indirectly: callers pass
// a cancellable filepath.WalkDir-style function or check ctx.Err()
// inside fn. We don't take a context here directly because the runner
// already does so at a coarser granularity (per-project), which is the
// right place to be responsive on a typical project.
func walkSourceFiles(root string, fn func(path string) error) (skipped []string, err error) {
	skippedSet := make(map[string]struct{})
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission errors and similar issues skip the offending
			// entry without aborting the whole walk. Returning err
			// here would propagate; we want best-effort coverage.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path == root {
				return nil
			}
			if shouldSkipDir(name) {
				skippedSet[name] = struct{}{}
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".py") {
			return nil
		}
		return fn(path)
	})
	for name := range skippedSet {
		skipped = append(skipped, name)
	}
	return skipped, walkErr
}

// shouldSkipDir reports whether the named subdirectory should be
// pruned during the walk. The list includes virtualenv layouts,
// common build outputs, and editor / VCS directories. Skipping
// site-packages is essential — it would otherwise scan installed
// dependency source as if it were the application.
func shouldSkipDir(name string) bool {
	switch name {
	case "venv", ".venv", "env", ".env",
		"__pycache__",
		"node_modules",
		".tox", ".nox",
		"build", "dist",
		".eggs",
		"site-packages",
		".git", ".hg", ".svn",
		".mypy_cache", ".pytest_cache", ".ruff_cache",
		".idea", ".vscode",
		"htmlcov", "coverage":
		return true
	}
	return strings.HasSuffix(name, ".egg-info")
}
