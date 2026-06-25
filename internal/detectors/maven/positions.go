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
	pomVersion         = regexp.MustCompile(`<version>([^<]+)</version>`)
)

// pomPositions returns name -> position by scanning every
// `<dependency>` block in pom.xml. The key is the bare artifactId
// (matching how the maven detector stores Name on graph packages).
// In multi-module projects with a single root pom, this is a
// best-effort attribution to the parent pom.
func pomPositions(path, relPath string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
	insideDep := false
	pendingGroup := ""
	pendingArtifactLine := 0
	pendingArtifactName := ""
	pendingVersion := ""
	pendingVersionLine := 0
	_ = detectors.ScanLines(path, func(line int, text string) {
		if pomDependencyOpen.MatchString(text) {
			insideDep = true
			pendingGroup = ""
			pendingArtifactLine = 0
			pendingArtifactName = ""
			pendingVersion = ""
			pendingVersionLine = 0
			return
		}
		if pomDependencyClose.MatchString(text) {
			if pendingArtifactName != "" && pendingArtifactLine > 0 {
				positionLine := pendingArtifactLine
				if pendingVersionLine > 0 {
					positionLine = pendingVersionLine
				}
				pos := &sdk.SourcePosition{File: relPath, Line: positionLine}
				appendPosition(out, pendingArtifactName, pos)
				if pendingVersion != "" {
					appendPosition(out, pendingArtifactName+"@"+pendingVersion, pos)
				}
				if pendingGroup != "" {
					appendPosition(out, pendingGroup+":"+pendingArtifactName, pos)
					if pendingVersion != "" {
						appendPosition(out, pendingGroup+":"+pendingArtifactName+"@"+pendingVersion, pos)
					}
				}
			}
			insideDep = false
			pendingGroup = ""
			pendingArtifactName = ""
			pendingArtifactLine = 0
			pendingVersion = ""
			pendingVersionLine = 0
			return
		}
		if !insideDep {
			return
		}
		if m := pomGroupID.FindStringSubmatch(text); m != nil {
			pendingGroup = strings.TrimSpace(m[1])
			return
		}
		if m := pomArtifactID.FindStringSubmatch(text); m != nil {
			pendingArtifactName = strings.TrimSpace(m[1])
			pendingArtifactLine = line
			return
		}
		if m := pomVersion.FindStringSubmatch(text); m != nil {
			pendingVersion = strings.TrimSpace(m[1])
			pendingVersionLine = line
		}
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
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		// Maven detector stores Name as artifactId (optionally with
		// :classifier suffix). Strip the suffix to match.
		name := strings.TrimSpace(pkg.Name)
		if i := strings.Index(name, ":"); i > 0 {
			name = name[:i]
		}
		version := strings.TrimSpace(pkg.Version)
		org := strings.TrimSpace(pkg.Org)
		return []string{org + ":" + name + "@" + version, name + "@" + version, org + ":" + name, name}
	})
}

func appendPosition(out map[string][]*sdk.SourcePosition, key string, pos *sdk.SourcePosition) {
	key = strings.TrimSpace(key)
	if key == "" || pos == nil {
		return
	}
	for _, existing := range out[key] {
		if existing.File == pos.File && existing.Line == pos.Line && existing.Column == pos.Column {
			return
		}
	}
	out[key] = append(out[key], pos)
}
