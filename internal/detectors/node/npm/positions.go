package npm

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// npmLockKeyLine matches a "packages" entry key in package-lock.json
// v2/v3, e.g. `    "node_modules/foo": {` or
// `    "node_modules/@scope/pkg": {`. Nested entries
// (`node_modules/foo/node_modules/bar`) are matched too — we then
// take the final segment as the package name.
var npmLockKeyLine = regexp.MustCompile(`^\s*"((?:node_modules/)+(?:@[^/"]+/)?[^"/]+)"\s*:\s*\{?\s*$`)

// packageLockPositions returns name -> SourcePosition for every
// node_modules/... key in package-lock.json. Multiple occurrences
// (nested installs) keep the first match.
func packageLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	_ = detectors.ScanLines(path, func(line int, text string) {
		matches := npmLockKeyLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := finalNPMPathSegment(matches[1])
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

// finalNPMPathSegment extracts the package name from a
// node_modules-style path. Handles scoped names by recognising the
// trailing "@scope/pkg" pattern.
func finalNPMPathSegment(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	if last == "" {
		return ""
	}
	// Scoped: previous segment must be "@scope".
	if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-2], "@") {
		return parts[len(parts)-2] + "/" + last
	}
	return last
}

// AttachPackageLockPositions populates Position on graph packages
// for every package whose name matches a node_modules/... key in
// package-lock.json.
func AttachPackageLockPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	lockPath := filepath.Join(projectDir, "package-lock.json")
	relPath := "package-lock.json"
	positions := packageLockPositions(lockPath, relPath)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		// Graph stores npm packages with their QualifiedName
		// ("@scope:pkg") or bare name. Try both forms.
		return strings.TrimSpace(pkg.Name)
	})
}
