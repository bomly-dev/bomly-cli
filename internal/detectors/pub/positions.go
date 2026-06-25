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
var pubspecLockEntry = regexp.MustCompile(`^ {2}([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$`)
var pubspecLockVersion = regexp.MustCompile(`^\s*version\s*:\s*"?([^"\s]+)"?`)

func pubspecLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	insidePackages := false
	pendingName := ""
	pendingLine := 0
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
		if matches := pubspecLockEntry.FindStringSubmatch(text); matches != nil {
			pendingName = matches[1]
			pendingLine = line
			return
		}
		if pendingName == "" {
			return
		}
		if pubspecLockVersion.FindStringSubmatch(text) == nil {
			return
		}
		if _, exists := out[pendingName]; !exists {
			out[pendingName] = &sdk.SourcePosition{File: relPath, Line: line}
		}
		pendingName = ""
		pendingLine = 0
	})
	if pendingName != "" {
		if _, exists := out[pendingName]; !exists {
			out[pendingName] = &sdk.SourcePosition{File: relPath, Line: pendingLine}
		}
	}
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
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
