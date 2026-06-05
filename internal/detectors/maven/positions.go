package maven

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// pomDependencyArtifactID matches an `<artifactId>foo</artifactId>`
// line. We scan pom.xml line-by-line tracking when we are inside a
// `<dependency>` block (vs. parent / plugin) and emit one position
// per artifact at the line of its artifactId tag.
var (
	pomDependencyOpen  = regexp.MustCompile(`<dependency>`)
	pomDependencyClose = regexp.MustCompile(`</dependency>`)
	pomGroupID         = regexp.MustCompile(`<groupId>([^<]+)</groupId>`)
	pomArtifactID      = regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
)

// pomPositions returns name -> position by scanning every
// `<dependency>` block in pom.xml. The key is the bare artifactId
// (matching how the maven detector stores Name on graph packages).
// In multi-module projects with a single root pom, this is a
// best-effort attribution to the parent pom.
func pomPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	insideDep := false
	pendingArtifactLine := 0
	pendingArtifactName := ""
	_ = detectors.ScanLines(path, func(line int, text string) {
		if pomDependencyOpen.MatchString(text) {
			insideDep = true
			pendingArtifactLine = 0
			pendingArtifactName = ""
			return
		}
		if pomDependencyClose.MatchString(text) {
			if pendingArtifactName != "" && pendingArtifactLine > 0 {
				if _, exists := out[pendingArtifactName]; !exists {
					out[pendingArtifactName] = &sdk.SourcePosition{File: relPath, Line: pendingArtifactLine}
				}
			}
			insideDep = false
			pendingArtifactName = ""
			pendingArtifactLine = 0
			return
		}
		if !insideDep {
			return
		}
		if m := pomArtifactID.FindStringSubmatch(text); m != nil {
			pendingArtifactName = strings.TrimSpace(m[1])
			pendingArtifactLine = line
			return
		}
		// groupId could be useful for disambiguation but we key only on
		// artifactId to match the graph's Name field.
		_ = pomGroupID
	})
	return out
}

// AttachPomPositions wires pom.xml line numbers into a maven graph.
func AttachPomPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := pomPositions(filepath.Join(projectDir, "pom.xml"), "pom.xml")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		// Maven detector stores Name as artifactId (optionally with
		// :classifier suffix). Strip the suffix to match.
		name := strings.TrimSpace(pkg.Name)
		if i := strings.Index(name, ":"); i > 0 {
			return name[:i]
		}
		return name
	})
}
