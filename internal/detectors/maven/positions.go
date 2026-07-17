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
	properties := pomProperties(path)
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
				versionLine := pendingVersionLine
				version := pendingVersion
				if propertyVersion, propertyLine, ok := pomResolvedPropertyVersion(pendingVersion, properties); ok {
					version = propertyVersion
					versionLine = propertyLine
				}
				if version == "" {
					if propertyVersion, propertyLine, ok := pomArtifactPropertyVersion(pendingArtifactName, properties); ok {
						version = propertyVersion
						versionLine = propertyLine
					}
				}
				artifactPos := &sdk.SourcePosition{File: relPath, Line: pendingArtifactLine}
				detectors.AppendPosition(out, pendingArtifactName, artifactPos)
				if pendingGroup != "" {
					detectors.AppendPosition(out, pendingGroup+":"+pendingArtifactName, artifactPos)
				}
				if version != "" {
					versionPos := artifactPos
					if versionLine > 0 {
						versionPos = &sdk.SourcePosition{File: relPath, Line: versionLine}
					}
					detectors.AppendPosition(out, pendingArtifactName+"@"+version, versionPos)
					if pendingGroup != "" {
						detectors.AppendPosition(out, pendingGroup+":"+pendingArtifactName+"@"+version, versionPos)
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

func pomProperties(path string) map[string]pomPropertyPosition {
	out := make(map[string]pomPropertyPosition)
	insideProperties := false
	_ = detectors.ScanLines(path, func(line int, text string) {
		if pomPropertiesOpen.MatchString(text) {
			insideProperties = true
			return
		}
		if pomPropertiesClose.MatchString(text) {
			insideProperties = false
			return
		}
		if !insideProperties {
			return
		}
		if m := pomProperty.FindStringSubmatch(text); m != nil {
			out[strings.TrimSpace(m[1])] = pomPropertyPosition{value: strings.TrimSpace(m[2]), line: line}
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

func pomArtifactPropertyVersion(artifact string, properties map[string]pomPropertyPosition) (string, int, bool) {
	artifact = strings.TrimSpace(artifact)
	if artifact == "" {
		return "", 0, false
	}
	prop, ok := properties[artifact+".version"]
	if !ok || prop.value == "" || prop.line == 0 {
		return "", 0, false
	}
	return prop.value, prop.line, true
}

// AttachPomPositions wires pom.xml line numbers into a maven graph. The pom
// is read from projectDir; relPomPath is the scan-root-relative pom path
// (e.g. "pom.xml" for the root, "core/pom.xml" for a reactor module) stamped
// into every recorded position, so multi-module locations stay repo-relative
// in SARIF and diff annotations.
func AttachPomPositions(g *sdk.Graph, projectDir, relPomPath string) {
	if g == nil || projectDir == "" {
		return
	}
	if relPomPath == "" {
		relPomPath = "pom.xml"
	}
	positions := pomPositions(filepath.Join(projectDir, "pom.xml"), relPomPath)
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
