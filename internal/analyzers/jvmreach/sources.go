package jvmreach

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// projectFileMarkers names every file whose presence at a directory
// makes that directory a JVM project root.
var projectFileMarkers = []string{
	"pom.xml",
	"build.gradle",
	"build.gradle.kts",
	"settings.gradle",
	"settings.gradle.kts",
	"build.sbt",
	"project.scala", // scala-cli
}

// hasProjectMarker returns true when dir contains any of the
// recognised JVM project files.
func hasProjectMarker(dir string) bool {
	for _, name := range projectFileMarkers {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// sourceFileExtensions are the file suffixes (lowercase) whose
// contents the analyzer scans for imports. The scanner itself is
// language-agnostic — Java / Kotlin / Scala / Groovy all share the
// same `import ...` line shape.
var sourceFileExtensions = []string{".java", ".kt", ".kts", ".scala", ".groovy"}

// walkSourceFiles invokes fn for every JVM source file under root,
// skipping common test / build / VCS / IDE / dependency-cache dirs.
// Returns the list of directory names actually skipped (for
// telemetry) and any walk error.
//
// Test sources are intentionally walked too: many real-world Java
// projects keep integration / smoke tests under src/main/test/...
// or use a non-standard layout, and reachability that's only
// triggered from tests is still real reachability for an audit.
// (A future refinement could separate runtime vs test reachability,
// matching the scope flag.)
func walkSourceFiles(root string, fn func(path string) error) (skipped []string, err error) {
	skippedSet := make(map[string]struct{})
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if hasProjectMarker(path) {
				skippedSet[name] = struct{}{}
				return filepath.SkipDir
			}
			if shouldSkipDir(name) {
				skippedSet[name] = struct{}{}
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		match := false
		for _, ext := range sourceFileExtensions {
			if strings.HasSuffix(lower, ext) {
				match = true
				break
			}
		}
		if !match {
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
// pruned during the walk. The list includes Maven/Gradle/SBT build
// outputs, dependency caches, IDE state, and VCS dirs. Skipping
// `target/`, `build/`, and `.gradle/` is essential — they may
// contain decompiled or extracted dependency source that would
// otherwise be misattributed as app code.
func shouldSkipDir(name string) bool {
	switch name {
	case "target", "build", "out", "bin",
		".gradle", ".m2", ".ivy2", ".sbt",
		".idea", ".vscode", ".eclipse", ".settings",
		".git", ".hg", ".svn",
		"node_modules",
		"generated", "generated-sources", "generated-test-sources":
		return true
	}
	return false
}
