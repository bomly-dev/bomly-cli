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
var nugetPackageReferenceVersionAttr = regexp.MustCompile(`(?i)\bVersion\s*=\s*"([^"]+)"`)
var nugetVersionElement = regexp.MustCompile(`(?i)<Version>\s*([^<]+)\s*</Version>`)
var nugetPackageReferenceClose = regexp.MustCompile(`(?i)</PackageReference>`)
var nugetPackagesConfigPackage = regexp.MustCompile(`(?i)<package\b[^>]*\bid\s*=\s*"([^"]+)"[^>]*\bversion\s*=\s*"([^"]+)"`)

// nugetLockfileEntry matches a `"foo": {` key inside packages.lock.json's
// dependencies map.
var nugetLockfileEntry = regexp.MustCompile(`^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)"\s*:\s*\{\s*$`)
var nugetLockResolvedLine = regexp.MustCompile(`^\s*"resolved"\s*:\s*"([^"]+)"`)

func nugetPositions(projectDir string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
	// 1) packages.lock.json: top-level dependency map entries.
	pendingName := ""
	pendingLine := 0
	_ = detectors.ScanLines(filepath.Join(projectDir, "packages.lock.json"), func(line int, text string) {
		if matches := nugetLockfileEntry.FindStringSubmatch(text); matches != nil {
			name := matches[1]
			if name == "" || name == "type" || name == "dependencies" || name == "contentHash" || name == "resolved" || name == "requested" {
				return
			}
			pendingName = strings.ToLower(name)
			pendingLine = line
			return
		}
		if pendingName == "" {
			return
		}
		matches := nugetLockResolvedLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		version := strings.TrimSpace(matches[1])
		pos := &sdk.SourcePosition{File: "packages.lock.json", Line: line}
		appendPosition(out, pendingName, &sdk.SourcePosition{File: "packages.lock.json", Line: pendingLine})
		appendPosition(out, pendingName+"@"+version, pos)
		pendingName = ""
		pendingLine = 0
	})
	// 2) Scan packages.config.
	_ = detectors.ScanLines(filepath.Join(projectDir, "packages.config"), func(line int, text string) {
		matches := nugetPackagesConfigPackage.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := strings.ToLower(strings.TrimSpace(matches[1]))
		version := strings.TrimSpace(matches[2])
		pos := &sdk.SourcePosition{File: "packages.config", Line: line}
		appendPosition(out, name, pos)
		appendPosition(out, name+"@"+version, pos)
	})
	// 3) Scan project files for PackageReference.
	projectFiles, _ := nugetProjectFiles(projectDir)
	for _, projFile := range projectFiles {
		rel, err := filepath.Rel(projectDir, projFile)
		if err != nil || rel == "" {
			rel = filepath.Base(projFile)
		}
		rel = filepath.ToSlash(rel)
		pendingName := ""
		pendingLine := 0
		_ = detectors.ScanLines(projFile, func(line int, text string) {
			refMatches := nugetPackageReference.FindStringSubmatch(text)
			if refMatches != nil {
				pendingName = strings.ToLower(strings.TrimSpace(refMatches[1]))
				pendingLine = line
				if versionMatches := nugetPackageReferenceVersionAttr.FindStringSubmatch(text); versionMatches != nil {
					version := strings.TrimSpace(versionMatches[1])
					pos := &sdk.SourcePosition{File: rel, Line: line}
					appendPosition(out, pendingName, pos)
					appendPosition(out, pendingName+"@"+version, pos)
					pendingName = ""
					pendingLine = 0
				}
				return
			}
			if pendingName == "" {
				return
			}
			if versionMatches := nugetVersionElement.FindStringSubmatch(text); versionMatches != nil {
				version := strings.TrimSpace(versionMatches[1])
				pos := &sdk.SourcePosition{File: rel, Line: line}
				appendPosition(out, pendingName, &sdk.SourcePosition{File: rel, Line: pendingLine})
				appendPosition(out, pendingName+"@"+version, pos)
				pendingName = ""
				pendingLine = 0
				return
			}
			if nugetPackageReferenceClose.MatchString(text) {
				appendPosition(out, pendingName, &sdk.SourcePosition{File: rel, Line: pendingLine})
				pendingName = ""
				pendingLine = 0
			}
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
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		name := strings.ToLower(strings.TrimSpace(pkg.Name))
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
