package yarn

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// yarnLockEntryHeader matches the start of a yarn.lock entry, e.g.
// `"foo@^1.0.0", "foo@^1.1.0":` or `foo@^1.0.0:` or
// `"@scope/pkg@^1.0.0":`. The entry header is a comma-separated list
// of `[package]@[range]` selectors terminated by `:`.
var yarnLockEntryHeader = regexp.MustCompile(`^"?((?:@[^/"@]+/)?[^/"@\s]+)@[^",:]+["']?(?:,\s*"?(?:@[^/"@]+/)?[^/"@\s]+@[^",:]+"?)*\s*:\s*$`)

func yarnLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	_ = detectors.ScanLines(path, func(line int, text string) {
		// Yarn lockfile entries are at column 0 (no indent).
		if strings.HasPrefix(text, " ") || strings.HasPrefix(text, "\t") {
			return
		}
		matches := yarnLockEntryHeader.FindStringSubmatch(text)
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

// AttachYarnLockPositions wires yarn.lock line numbers.
func AttachYarnLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := yarnLockPositions(filepath.Join(projectDir, "yarn.lock"), "yarn.lock")
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		return strings.TrimSpace(pkg.Name)
	})
}
