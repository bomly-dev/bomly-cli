package swiftpm

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// swiftPMIdentity matches an `"identity": "foo"` line in
// Package.resolved (both v1 and v2 formats use this key).
var swiftPMIdentity = regexp.MustCompile(`"identity"\s*:\s*"([^"]+)"`)
var swiftPMVersion = regexp.MustCompile(`"(?:version|revision)"\s*:\s*"([^"]+)"`)

func packageResolvedPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	pendingName := ""
	pendingLine := 0
	_ = detectors.ScanLines(path, func(line int, text string) {
		if matches := swiftPMIdentity.FindStringSubmatch(text); matches != nil {
			pendingName = strings.ToLower(strings.TrimSpace(matches[1]))
			pendingLine = line
			return
		}
		if pendingName == "" {
			return
		}
		if swiftPMVersion.FindStringSubmatch(text) == nil {
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

// AttachPackageResolvedPositions wires Package.resolved line numbers
// into the graph. Identity is matched case-insensitively because the
// SwiftPM detector lowercases names on graph construction.
func AttachPackageResolvedPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	candidates := []string{
		"Package.resolved",
		filepath.Join(".swiftpm", "xcode", "package.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"),
		filepath.Join("project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"),
	}
	merged := make(map[string]*sdk.SourcePosition)
	for _, rel := range candidates {
		got := packageResolvedPositions(filepath.Join(projectDir, rel), filepath.ToSlash(rel))
		for k, v := range got {
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		}
	}
	if len(merged) == 0 {
		return
	}
	detectors.AttachPositions(g, merged, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(pkg.Name))
	})
}
