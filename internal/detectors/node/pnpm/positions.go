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
var pnpmLockKeyLine = regexp.MustCompile(`^\s*['"]?/?((?:@[^/'"@]+/)?[^/'"@\s]+)[@/]([^:'"\s(]+)`)

func pnpmLockPositions(path, relPath string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
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
		version := strings.TrimSpace(matches[2])
		pos := &sdk.SourcePosition{File: relPath, Line: line}
		if version != "" {
			appendPosition(out, name+"@"+version, pos)
		}
		appendPosition(out, name, pos)
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
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			return nil
		}
		return []string{name + "@" + strings.TrimSpace(pkg.Version), name}
	})
}

func appendPosition(out map[string][]*sdk.SourcePosition, key string, pos *sdk.SourcePosition) {
	key = strings.TrimSpace(key)
	if key == "" || pos == nil {
		return
	}
	for _, existing := range out[key] {
		if existing.File == pos.File && existing.Line == pos.Line && existing.Column == pos.Column {
			return
		}
	}
	out[key] = append(out[key], pos)
}
