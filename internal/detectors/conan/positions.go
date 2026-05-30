package conan

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// conanRequireLine matches a Conan require line of the form
// `name/version[@user/channel]` typically found in conanfile.txt's
// [requires] / [build_requires] / [tool_requires] sections. The
// captured value is the package name.
var conanRequireLine = regexp.MustCompile(`^\s*([a-zA-Z0-9_][a-zA-Z0-9._+-]*)\s*/\s*[^@\s]+`)

var conanSectionHeader = regexp.MustCompile(`^\s*\[\s*(requires|build_requires|tool_requires|test_requires)\s*\]\s*$`)

func conanPositions(projectDir string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	candidates := []string{"conanfile.txt", "conan.lock", "conaninfo.txt"}
	for _, name := range candidates {
		full := filepath.Join(projectDir, name)
		insideRequires := name == "conan.lock" || name == "conaninfo.txt" // always scan lock/info bodies
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
			matches := conanRequireLine.FindStringSubmatch(text)
			if matches == nil {
				return
			}
			pkgName := strings.TrimSpace(matches[1])
			if pkgName == "" {
				return
			}
			if _, exists := out[pkgName]; exists {
				return
			}
			out[pkgName] = &sdk.SourcePosition{File: name, Line: line}
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
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
