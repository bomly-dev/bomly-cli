package conan

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

var conanRefLine = regexp.MustCompile(`([a-zA-Z0-9_][a-zA-Z0-9._+-]*)\s*/\s*([^@'"\s,)]+)`)

var conanSectionHeader = regexp.MustCompile(`^\s*\[\s*(requires|build_requires|tool_requires|test_requires)\s*\]\s*$`)

func conanPositions(projectDir string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
	candidates := []string{"conanfile.txt", "conanfile.py", "conan.lock", "conaninfo.txt"}
	for _, name := range candidates {
		full := filepath.Join(projectDir, name)
		insideRequires := name == "conan.lock" || name == "conaninfo.txt" || name == "conanfile.py" // always scan lock/info/python bodies
		_ = detectors.ScanLines(full, func(line int, text string) {
			trimmed := strings.TrimSpace(text)
			if conanSectionHeader.MatchString(trimmed) {
				insideRequires = true
				return
			}
			if name == "conanfile.txt" && strings.HasPrefix(trimmed, "[") {
				insideRequires = false
				return
			}
			if !insideRequires {
				return
			}
			matches := conanRefLine.FindStringSubmatch(text)
			if matches == nil {
				return
			}
			pkgName := strings.TrimSpace(matches[1])
			if pkgName == "" {
				return
			}
			version := strings.TrimSpace(matches[2])
			pos := &sdk.SourcePosition{File: name, Line: line}
			appendPosition(out, pkgName, pos)
			if version != "" {
				appendPosition(out, pkgName+"@"+version, pos)
			}
		})
	}
	return out
}

// AttachConanPositions wires conanfile.txt / conan.lock line numbers.
func AttachConanPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := conanPositions(projectDir)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			return nil
		}
		return []string{name + "@" + strings.TrimSpace(pkg.Version), name}
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
