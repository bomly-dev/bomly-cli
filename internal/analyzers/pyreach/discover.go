package pyreach

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// discoverProjectRoots returns the Python project roots derivable
// from the request, in priority order:
//
//  1. Each Python package's PackageLocation.RealPath: walk upward to
//     the nearest directory containing a recognised project file
//     (pyproject.toml, setup.py, requirements.txt, …). Skip
//     directories inside venv/, site-packages/, etc. — those describe
//     installed dependencies, not project roots.
//  2. The request's ProjectPath / ExecutionTarget.Location, when it
//     itself contains a project file.
//
// Paths are normalized with filepath.Clean. Duplicates are removed
// and results are sorted for deterministic ordering.
func discoverProjectRoots(req model.AnalyzeRequest) []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0)

	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		roots = append(roots, clean)
	}

	if req.Graph != nil {
		for _, pkg := range req.Graph.Packages() {
			if pkg == nil || !isPythonPackage(pkg) {
				continue
			}
			for _, loc := range pkg.Locations {
				if loc.RealPath == "" {
					continue
				}
				if root := findProjectRoot(loc.RealPath); root != "" {
					add(root)
				}
			}
		}
	}

	for _, candidate := range []string{req.ProjectPath, req.ExecutionTarget.Location} {
		if candidate == "" {
			continue
		}
		if root := findProjectRoot(candidate); root != "" {
			add(root)
		}
	}

	sort.Strings(roots)
	return roots
}

// findProjectRoot walks upward from start until it finds a directory
// that looks like a Python project root (contains any recognised
// project file). Returns "" when none is found before reaching the
// filesystem root or hitting a path that is itself inside a venv /
// site-packages tree.
func findProjectRoot(start string) string {
	dir := start
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if dir == "" {
			return ""
		}
		if isInsideVendoredTree(dir) {
			// Walking through a venv / site-packages would attribute
			// dep source to the project. Bail out when we recognise
			// we're below such a directory.
			parent := filepath.Dir(dir)
			if parent == dir {
				return ""
			}
			dir = parent
			continue
		}
		if hasProjectMarker(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isInsideVendoredTree reports whether dir is itself inside a venv,
// site-packages, or similar dependency tree. We must skip these
// because their pyproject.toml / setup.py describe installed
// dependencies, not the application.
func isInsideVendoredTree(dir string) bool {
	normalized := filepath.ToSlash(dir)
	markers := []string{
		"/site-packages/",
		"/venv/",
		"/.venv/",
		"/node_modules/",
		"/__pycache__/",
		"/.tox/",
		"/.nox/",
	}
	for _, m := range markers {
		if strings.Contains(normalized, m) {
			return true
		}
	}
	return false
}

// isPythonPackage reports whether pkg's ecosystem or build system
// identifies it as a Python (PyPI) package. Mirrors the equivalent
// helpers in govulncheck and jsreach.
func isPythonPackage(pkg *model.Package) bool {
	if pkg == nil {
		return false
	}
	if strings.EqualFold(pkg.Ecosystem, string(model.EcosystemPython)) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.BuildSystem)) {
	case "pip", "pipenv", "poetry", "uv", "pdm", "setuppy", "setup.py":
		return true
	}
	return strings.EqualFold(pkg.Language, string(model.LanguagePython))
}
