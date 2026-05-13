package composer

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// composerNameLine matches `"name": "vendor/pkg"` inside composer.lock.
var composerNameLine = regexp.MustCompile(`^\s*"name"\s*:\s*"([^"]+)"\s*,?\s*$`)

func composerLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	_ = detectors.ScanLines(path, func(line int, text string) {
		matches := composerNameLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := strings.TrimSpace(matches[1])
		if name == "" || !strings.Contains(name, "/") {
			return
		}
		if _, exists := out[name]; exists {
			return
		}
		out[name] = &sdk.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// AttachComposerLockPositions wires composer.lock line numbers.
func AttachComposerLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := composerLockPositions(filepath.Join(projectDir, "composer.lock"), "composer.lock")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		// Composer packages are vendor/pkg. Graph stores Name as the
		// full coordinate, occasionally Org=vendor + Name=pkg. Try
		// both forms.
		if pkg.Org != "" && pkg.Name != "" {
			return pkg.Org + "/" + pkg.Name
		}
		return strings.TrimSpace(pkg.Name)
	})
}
