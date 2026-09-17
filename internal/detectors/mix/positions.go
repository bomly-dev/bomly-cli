package mix

import (
	"path/filepath"
	"regexp"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

// mixLockEntry matches a `"foo": {:hex, ...},` entry inside mix.lock.
// mix.lock is an Elixir map literal where keys are atom-string'd
// names.
var mixLockEntry = regexp.MustCompile(`^\s*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*\{`)

func mixLockPositions(path, relPath string) map[string]*model.SourcePosition {
	out := make(map[string]*model.SourcePosition)
	_ = detectors.ScanLines(path, func(line int, text string) {
		matches := mixLockEntry.FindStringSubmatch(text)
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
		out[name] = &model.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// AttachMixLockPositions wires mix.lock line numbers.
func AttachMixLockPositions(g *model.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := mixLockPositions(filepath.Join(projectDir, "mix.lock"), "mix.lock")
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
