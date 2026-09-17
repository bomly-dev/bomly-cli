package cocoapods

import (
	"path/filepath"
	"regexp"
	"strings"

	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

// podfileLockSpec matches a Podfile.lock spec entry. Examples:
//
//   - AFNetworking (4.0.1):
//   - AFNetworking/NSURLSession (4.0.1)
//
// The captured name is the bare pod name without subspec slashes.
var podfileLockSpec = regexp.MustCompile(`^\s*-\s+([A-Za-z0-9_-][A-Za-z0-9._/-]*)\s*\(([^)]+)\)\s*:?\s*$`)

func podfileLockPositions(path, relPath string) map[string]*model.SourcePosition {
	out := make(map[string]*model.SourcePosition)
	insideSpecs := false
	_ = detectors.ScanLines(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		if trimmed == "PODS:" {
			insideSpecs = true
			return
		}
		if !strings.HasPrefix(text, " ") && !strings.HasPrefix(text, "\t") && strings.HasSuffix(trimmed, ":") && trimmed != "PODS:" {
			insideSpecs = false
			return
		}
		if !insideSpecs {
			return
		}
		matches := podfileLockSpec.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := matches[1]
		// Strip subspec path so the bare pod name is the key.
		if i := strings.Index(name, "/"); i > 0 {
			name = name[:i]
		}
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

// AttachPodfileLockPositions wires Podfile.lock line numbers.
func AttachPodfileLockPositions(g *model.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := podfileLockPositions(filepath.Join(projectDir, "Podfile.lock"), "Podfile.lock")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *model.DependencyNode) string {
		if pkg == nil {
			return ""
		}
		name := strings.TrimSpace(pkg.Name)
		if i := strings.Index(name, "/"); i > 0 {
			return name[:i]
		}
		return name
	})
}
