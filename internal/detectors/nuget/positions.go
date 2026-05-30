package nuget

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// nugetPackageReference matches `<PackageReference Include="Foo" Version="..." />`
// or `<PackageReference Include="Foo">...</PackageReference>` lines.
// Captures the Include name. Case-insensitive on the attribute name
// because some projects use Pascal/Camel.
var nugetPackageReference = regexp.MustCompile(`(?i)<PackageReference\b[^>]*\bInclude\s*=\s*"([^"]+)"`)

// nugetLockfileEntry matches a `"foo": {` key inside packages.lock.json's
// dependencies map.
var nugetLockfileEntry = regexp.MustCompile(`^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)"\s*:\s*\{\s*$`)

func nugetPositions(projectDir string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	// 1) packages.lock.json: top-level dependency map entries.
	_ = detectors.ScanLines(filepath.Join(projectDir, "packages.lock.json"), func(line int, text string) {
		matches := nugetLockfileEntry.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := matches[1]
		if name == "" || name == "type" || name == "dependencies" || name == "contentHash" || name == "resolved" || name == "requested" {
			return
		}
		key := strings.ToLower(name)
		if _, exists := out[key]; exists {
			return
		}
		out[key] = &sdk.SourcePosition{File: "packages.lock.json", Line: line}
	})
	// 2) Scan *.csproj, *.fsproj, *.vbproj for PackageReference.
	matches, _ := filepath.Glob(filepath.Join(projectDir, "*.csproj"))
	fs, _ := filepath.Glob(filepath.Join(projectDir, "*.fsproj"))
	vs, _ := filepath.Glob(filepath.Join(projectDir, "*.vbproj"))
	matches = append(matches, fs...)
	matches = append(matches, vs...)
	for _, projFile := range matches {
		rel := filepath.Base(projFile)
		_ = detectors.ScanLines(projFile, func(line int, text string) {
			refMatches := nugetPackageReference.FindStringSubmatch(text)
			if refMatches == nil {
				return
			}
			name := strings.TrimSpace(refMatches[1])
			if name == "" {
				return
			}
			key := strings.ToLower(name)
			if _, exists := out[key]; exists {
				return
			}
			out[key] = &sdk.SourcePosition{File: rel, Line: line}
		})
	}
	return out
}

// AttachNugetPositions wires .csproj / packages.lock.json line
// numbers into a nuget-resolved graph.
func AttachNugetPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := nugetPositions(projectDir)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(pkg.Name))
	})
}
