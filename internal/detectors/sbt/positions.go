package sbt

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// sbtLibraryDep matches the typical Scala SBT dependency declaration:
//
//	libraryDependencies += "org.foo" % "bar" % "1.0.0"
//	libraryDependencies += "org.foo" %% "bar" % "1.0.0" % Test
//	"org.foo" % "bar" % "1.0.0"     (inside a Seq(...))
//
// The captured artifact is the second `"..."`.
var sbtLibraryDep = regexp.MustCompile(`["']([a-zA-Z0-9][a-zA-Z0-9._-]*)["']\s*%{1,3}\s*["']([a-zA-Z0-9][a-zA-Z0-9._-]*)["']\s*%`)

func sbtPositions(projectDir string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	files := []string{
		"build.sbt",
		filepath.Join("project", "build.sbt"),
		filepath.Join("project", "Dependencies.scala"),
		filepath.Join("project", "plugins.sbt"),
	}
	for _, rel := range files {
		full := filepath.Join(projectDir, rel)
		_ = detectors.ScanLines(full, func(line int, text string) {
			matches := sbtLibraryDep.FindStringSubmatch(text)
			if matches == nil {
				return
			}
			name := strings.TrimSpace(matches[2])
			if name == "" {
				return
			}
			if _, exists := out[name]; exists {
				return
			}
			out[name] = &sdk.SourcePosition{File: filepath.ToSlash(rel), Line: line}
		})
	}
	return out
}

// AttachSBTPositions wires build.sbt / Dependencies.scala line
// numbers into an SBT-resolved graph.
func AttachSBTPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := sbtPositions(projectDir)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		// SBT graph packages typically expose Name=artifact (with
		// optional `_<scala-version>` suffix appended for cross
		// builds). Strip the suffix when present.
		name := strings.TrimSpace(pkg.Name)
		if i := strings.LastIndex(name, "_"); i > 0 {
			// Heuristic: a `_2.12` / `_3` suffix is a Scala binary
			// version. Strip only when the suffix looks numeric.
			suffix := name[i+1:]
			if looksLikeScalaVersion(suffix) {
				return name[:i]
			}
		}
		return name
	})
}

func looksLikeScalaVersion(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
