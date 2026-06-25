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
var npmLockKeyLine = regexp.MustCompile(`^\s*"((?:.*node_modules/)(?:@[^/"]+/)?[^"/]+)"\s*:\s*\{?\s*$`)
var npmLockVersionLine = regexp.MustCompile(`^\s*"version"\s*:\s*"([^"]+)"`)

// packageLockPositions returns lookup keys for every node_modules/... key in
// package-lock.json. Exact name@version keys point at the version line, while
// name-only fallback keys point at the package block key.
func packageLockPositions(path, relPath string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
	var currentName string
	var currentLine int
	_ = detectors.ScanLines(path, func(line int, text string) {
		if matches := npmLockKeyLine.FindStringSubmatch(text); matches != nil {
			currentName = finalNPMPathSegment(matches[1])
			currentLine = line
			return
		}
		if currentName == "" {
			return
		}
		matches := npmLockVersionLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		version := strings.TrimSpace(matches[1])
		pos := &sdk.SourcePosition{File: relPath, Line: line}
		if version != "" {
			appendPosition(out, currentName+"@"+version, pos)
		}
		appendPosition(out, currentName, &sdk.SourcePosition{File: relPath, Line: currentLine})
		currentName = ""
		currentLine = 0
	})
	return out
}

// finalNPMPathSegment extracts the package name from a
// node_modules-style path. Handles scoped names by recognizing the
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
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		// Graph stores npm packages with their QualifiedName
		// ("@scope:pkg") or bare name. Try both forms.
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
