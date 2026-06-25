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
	pomPropertiesOpen  = regexp.MustCompile(`<properties>`)
	pomPropertiesClose = regexp.MustCompile(`</properties>`)
	pomGroupID         = regexp.MustCompile(`<groupId>([^<]+)</groupId>`)
	pomArtifactID      = regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
	pomVersion         = regexp.MustCompile(`<version>([^<]+)</version>`)
	pomProperty        = regexp.MustCompile(`^\s*<([A-Za-z0-9_.-]+)>\s*([^<]+)\s*</[A-Za-z0-9_.-]+>\s*$`)
	pomPropertyRef     = regexp.MustCompile(`^\$\{([A-Za-z0-9_.-]+)\}$`)
)

type pomPropertyPosition struct {
	value string
	line  int
}

// pomPositions returns name -> position by scanning every
// `<dependency>` block in pom.xml. The key is the bare artifactId
// (matching how the maven detector stores Name on graph packages).
// In multi-module projects with a single root pom, this is a
// best-effort attribution to the parent pom.
func pomPositions(path, relPath string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
	properties := make(map[string]pomPropertyPosition)
	insideProperties := false
	insideDep := false
	pendingGroup := ""
	pendingArtifactLine := 0
	pendingArtifactName := ""
	pendingVersion := ""
	pendingVersionLine := 0
	_ = detectors.ScanLines(path, func(line int, text string) {
		if !insideDep {
			if pomPropertiesOpen.MatchString(text) {
				insideProperties = true
				return
			}
			if pomPropertiesClose.MatchString(text) {
				insideProperties = false
				return
			}
			if insideProperties {
				if m := pomProperty.FindStringSubmatch(text); m != nil {
					properties[strings.TrimSpace(m[1])] = pomPropertyPosition{value: strings.TrimSpace(m[2]), line: line}
				}
				return
			}
		}
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
				version := pendingVersion
				if pendingVersionLine > 0 {
					positionLine = pendingVersionLine
				}
				if propertyVersion, propertyLine, ok := pomResolvedPropertyVersion(pendingVersion, properties); ok {
					version = propertyVersion
					positionLine = propertyLine
				}
				pos := &sdk.SourcePosition{File: relPath, Line: positionLine}
				detectors.AppendPosition(out, pendingArtifactName, pos)
				if version != "" {
					detectors.AppendPosition(out, pendingArtifactName+"@"+version, pos)
				}
				if pendingGroup != "" {
					detectors.AppendPosition(out, pendingGroup+":"+pendingArtifactName, pos)
					if version != "" {
						detectors.AppendPosition(out, pendingGroup+":"+pendingArtifactName+"@"+version, pos)
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

func pomResolvedPropertyVersion(version string, properties map[string]pomPropertyPosition) (string, int, bool) {
	matches := pomPropertyRef.FindStringSubmatch(strings.TrimSpace(version))
	if matches == nil {
		return "", 0, false
	}
	prop, ok := properties[matches[1]]
	if !ok || prop.value == "" || prop.line == 0 {
		return "", 0, false
	}
	return prop.value, prop.line, true
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
