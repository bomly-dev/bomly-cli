package cargo

import (
	"path/filepath"
	"regexp"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

var (
	cargoPackageHeader = regexp.MustCompile(`^\s*\[\[\s*package\s*\]\]\s*$`)
	cargoNameLine      = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"\s*$`)
)

func cargoLockPositions(path, relPath string) map[string]*model.SourcePosition {
	out := make(map[string]*model.SourcePosition)
	inBlock := false
	_ = detectors.ScanLines(path, func(line int, text string) {
		switch {
		case cargoPackageHeader.MatchString(text):
			inBlock = true
		case inBlock:
			matches := cargoNameLine.FindStringSubmatch(text)
			if matches != nil {
				name := strings.TrimSpace(matches[1])
				if name != "" {
					if _, exists := out[name]; !exists {
						out[name] = &model.SourcePosition{File: relPath, Line: line}
					}
				}
				inBlock = false
				return
			}
			if strings.HasPrefix(strings.TrimSpace(text), "[") {
				inBlock = false
			}
		}
	})
	return out
}

// AttachCargoLockPositions wires Cargo.lock line numbers into the graph.
func AttachCargoLockPositions(g *model.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := cargoLockPositions(filepath.Join(projectDir, "Cargo.lock"), "Cargo.lock")
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
