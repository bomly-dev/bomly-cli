package pnpm

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// pnpmLockKeyLine matches top-level `packages:` entries in pnpm-lock.yaml.
// Examples accepted:
//
//	'foo@1.0.0':
//	/foo/1.0.0:
//	'/foo@1.0.0(transitivePeer@2.0.0)':
//	'@scope/pkg@1.0.0':
var pnpmLockKeyLine = regexp.MustCompile(`^\s*['"]?/?((?:@[^/'"@]+/)?[^/'"@\s]+)[@/][^:'"\s]+['"]?\s*:\s*$`)

func pnpmLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	insidePackages := false
	_ = detectors.ScanLines(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		if trimmed == "packages:" {
			insidePackages = true
			return
		}
		// Other top-level YAML keys end the packages: section.
		if !strings.HasPrefix(text, " ") && !strings.HasPrefix(text, "\t") && strings.HasSuffix(trimmed, ":") && trimmed != "packages:" {
			insidePackages = false
			return
		}
		if !insidePackages {
			return
		}
		matches := pnpmLockKeyLine.FindStringSubmatch(text)
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

// AttachPnpmLockPositions wires pnpm-lock.yaml line numbers.
func AttachPnpmLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := pnpmLockPositions(filepath.Join(projectDir, "pnpm-lock.yaml"), "pnpm-lock.yaml")
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
