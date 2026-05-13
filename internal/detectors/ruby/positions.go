package ruby

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// gemSpecLine matches a top-level gem spec line inside the GEM/specs:
// block of a Gemfile.lock. Example: "    railties (8.0.0)".
// The 4-space indent distinguishes spec lines from the deeper-indented
// dependency lines (6 spaces).
var gemSpecLine = regexp.MustCompile(`^    ([a-zA-Z0-9._-]+) \(([^)]+)\)\s*$`)

// gemfileLockPositions returns a map from gem name to the line in
// Gemfile.lock where the gem's spec entry appears.
func gemfileLockPositions(lockPath, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	_ = detectors.ScanLines(lockPath, func(line int, text string) {
		matches := gemSpecLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := strings.TrimSpace(matches[1])
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

// AttachGemfileLockPositions wires Gemfile.lock line numbers into
// the resolved graph.
func AttachGemfileLockPositions(g *sdk.Graph, lockPath, projectDir string) {
	if g == nil || lockPath == "" {
		return
	}
	rel, err := filepath.Rel(projectDir, lockPath)
	if err != nil || rel == "" {
		rel = filepath.Base(lockPath)
	}
	rel = filepath.ToSlash(rel)
	positions := gemfileLockPositions(lockPath, rel)
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
