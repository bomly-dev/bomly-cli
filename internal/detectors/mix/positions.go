package mix

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// mixLockEntry matches a `"foo": {:hex, ...},` entry inside mix.lock.
// mix.lock is an Elixir map literal where keys are atom-string'd
// names.
var mixLockEntry = regexp.MustCompile(`^\s*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*\{`)

func mixLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
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
		out[name] = &sdk.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// AttachMixLockPositions wires mix.lock line numbers.
func AttachMixLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := mixLockPositions(filepath.Join(projectDir, "mix.lock"), "mix.lock")
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
