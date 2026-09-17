package pub

import (
	"path/filepath"
	"regexp"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

// pubspecLockEntry matches a top-level entry under `packages:` in
// pubspec.lock, indented by two spaces and ending in a colon.
var pubspecLockEntry = regexp.MustCompile(`^ {2}([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$`)
var pubspecLockVersion = regexp.MustCompile(`^\s*version\s*:\s*"?([^"\s]+)"?`)

func pubspecLockPositions(path, relPath string) map[string]*model.SourcePosition {
	out := make(map[string]*model.SourcePosition)
	insidePackages := false
	pendingName := ""
	pendingLine := 0
	flush := func() {
		if pendingName == "" || pendingLine == 0 {
			return
		}
		if _, exists := out[pendingName]; !exists {
			out[pendingName] = &model.SourcePosition{File: relPath, Line: pendingLine}
		}
		pendingName = ""
		pendingLine = 0
	}
	_ = detectors.ScanLines(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		if trimmed == "packages:" {
			flush()
			insidePackages = true
			return
		}
		if !strings.HasPrefix(text, " ") && strings.HasSuffix(trimmed, ":") {
			flush()
			insidePackages = trimmed == "packages:"
			return
		}
		if !insidePackages {
			return
		}
		if matches := pubspecLockEntry.FindStringSubmatch(text); matches != nil {
			flush()
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
			out[pendingName] = &model.SourcePosition{File: relPath, Line: line}
		}
		pendingName = ""
		pendingLine = 0
	})
	flush()
	return out
}

// AttachPubspecLockPositions wires pubspec.lock line numbers.
func AttachPubspecLockPositions(g *model.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := pubspecLockPositions(filepath.Join(projectDir, "pubspec.lock"), "pubspec.lock")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *model.DependencyNode) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
