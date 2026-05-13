package pub

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// pubspecLockEntry matches a top-level entry under `packages:` in
// pubspec.lock, indented by two spaces and ending in a colon.
var pubspecLockEntry = regexp.MustCompile(`^  ([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$`)

func pubspecLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	insidePackages := false
	_ = detectors.ScanLines(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		if trimmed == "packages:" {
			insidePackages = true
			return
		}
		if !strings.HasPrefix(text, " ") && strings.HasSuffix(trimmed, ":") {
			insidePackages = trimmed == "packages:"
			return
		}
		if !insidePackages {
			return
		}
		matches := pubspecLockEntry.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := matches[1]
		if name == "" {
			return
		}
		if _, exists := out[name]; exists {
			return
		}
		out[name] = &sdk.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// AttachPubspecLockPositions wires pubspec.lock line numbers.
func AttachPubspecLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := pubspecLockPositions(filepath.Join(projectDir, "pubspec.lock"), "pubspec.lock")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
