package jvmreach

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// discoverProjectRoots returns the JVM project roots derivable from
// the request.
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
		for _, pkg := range req.Graph.Nodes() {
			if pkg == nil || !isJVMPackage(pkg) {
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
// that contains a recognised JVM project file. Returns "" when none
// is found.
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

// isJVMPackage reports whether pkg's ecosystem, build system, or
// language identifies it as a JVM (Maven/Gradle/SBT) package.
func isJVMPackage(pkg *model.Dependency) bool {
	if pkg == nil {
		return false
	}
	switch strings.ToLower(pkg.Ecosystem) {
	case string(model.EcosystemMaven), string(model.EcosystemScala):
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.BuildSystem)) {
	case "maven", "gradle", "sbt":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.Language)) {
	case string(model.LanguageJava), string(model.LanguageKotlin),
		string(model.LanguageScala), string(model.LanguageGroovy):
		return true
	}
	return false
}
