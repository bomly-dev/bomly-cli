package gradle

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// gradleDependencyCoord matches the typical declarations in
// build.gradle / build.gradle.kts:
//
//	implementation 'com.foo:bar:1.0.0'
//	implementation("com.foo:bar:1.0.0")
//	compile group: 'com.foo', name: 'bar', version: '1.0.0'
//	api("com.foo:bar:1.0.0")
//
// We capture the artifactId from the coordinate when the
// single-string form is used. The map: form is not currently matched.
var gradleDependencyCoord = regexp.MustCompile(`["']([a-zA-Z][a-zA-Z0-9._-]+):([a-zA-Z0-9][a-zA-Z0-9._-]*):[^"'\s)]+["']`)

// gradleNameKwArg matches `name: "bar"` / `name = "bar"` style.
var gradleNameKwArg = regexp.MustCompile(`name\s*[:=]\s*["']([a-zA-Z0-9][a-zA-Z0-9._-]*)["']`)

// gradleLockfileLine matches a line in gradle.lockfile:
//
//	com.foo:bar:1.0.0=configuration1,configuration2
var gradleLockfileLine = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9._-]+):([a-zA-Z0-9][a-zA-Z0-9._-]*):[^=]+=`)

// gradlePositions scans the build files in projectDir and returns
// artifactId -> SourcePosition. build.gradle, build.gradle.kts, and
// gradle.lockfile are all walked; the first match per artifactId
// wins. relDir is the scan-root-relative subproject directory (slash
// form, empty for the root project) prefixed onto every recorded file
// so multi-project locations stay repo-relative.
func gradlePositions(projectDir, relDir string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	files := []string{
		"gradle.lockfile",
		"build.gradle.kts",
		"build.gradle",
		"settings.gradle.kts",
		"settings.gradle",
	}
	for _, name := range files {
		full := filepath.Join(projectDir, name)
		relFile := name
		if relDir != "" && relDir != "." {
			relFile = relDir + "/" + name
		}
		_ = detectors.ScanLines(full, func(line int, text string) {
			// Lockfile lines (com.foo:bar:1.0.0=...).
			if m := gradleLockfileLine.FindStringSubmatch(text); m != nil {
				record(out, relFile, m[2], line)
				return
			}
			// Source-coordinate string form.
			if m := gradleDependencyCoord.FindStringSubmatch(text); m != nil {
				record(out, relFile, m[2], line)
				return
			}
			// keyword-arg map form (only the name= portion).
			if m := gradleNameKwArg.FindStringSubmatch(text); m != nil {
				record(out, relFile, m[1], line)
				return
			}
		})
	}
	return out
}

func record(out map[string]*sdk.SourcePosition, file, name string, line int) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if _, exists := out[name]; exists {
		return
	}
	out[name] = &sdk.SourcePosition{File: file, Line: line}
}

// AttachGradlePositions wires gradle build/lock file line numbers
// into a gradle-resolved graph. Build files are read from projectDir;
// relDir is the scan-root-relative subproject directory (slash form,
// empty for the root project) used to keep recorded file paths
// repo-relative.
func AttachGradlePositions(g *sdk.Graph, projectDir, relDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := gradlePositions(projectDir, relDir)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Dependency) string {
		if pkg == nil {
			return ""
		}
		name := strings.TrimSpace(pkg.Name)
		if i := strings.Index(name, ":"); i > 0 {
			return name[:i]
		}
		return name
	})
}
