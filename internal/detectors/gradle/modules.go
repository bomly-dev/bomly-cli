package gradle

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// gradleModule is one subproject declared by the build's settings script: its
// Gradle project path (":app", ":services:api"), the directory it lives in
// relative to the build root (slash form), the project name Gradle derives
// from the last path segment, the group its build script declares (falling
// back to the root project's group), and the build script file name the
// module's manifest entry should point at.
type gradleModule struct {
	ProjectPath  string
	Dir          string
	Name         string
	Group        string
	ManifestFile string
}

// The declaration regexes run over comment-stripped script text (see
// stripGradleComments) and are line-anchored, so commented-out declarations
// and include-shaped text inside unrelated string literals never register as
// modules.
var (
	gradleParenthesizedInclude = regexp.MustCompile(`(?ms)^[ \t]*include\s*\((.*?)\)`)
	gradleLineInclude          = regexp.MustCompile(`(?m)^[ \t]*include\s+([^\r\n(][^\r\n]*)$`)
	gradleQuotedValue          = regexp.MustCompile(`["']([^"']+)["']`)
	gradleProjectDirOverride   = regexp.MustCompile(`(?m)^[ \t]*project\s*\(\s*["']([^"']+)["']\s*\)\.projectDir\s*=\s*file\s*\(\s*["']([^"']+)["']\s*\)`)
	gradleGroupAssignment      = regexp.MustCompile(`(?m)^\s*group\s*=\s*["']([^"']+)["']`)
)

// stripGradleComments removes line (//) and block (/* ... */) comments from a
// Gradle script while preserving string literals and line structure, so the
// line-anchored declaration regexes never match commented-out code. It is a
// lightweight scanner, not a Groovy/Kotlin lexer: single- and double-quoted
// strings (with backslash escapes) pass through verbatim, triple-quoted
// multiline strings (Kotlin """raw""" / Groovy '''...''') are blanked down to
// their newlines — their inner lines would otherwise satisfy the line-anchored
// regexes, and no legitimate declaration lives inside one — block comments
// keep their newlines, and everything else is copied as-is.
func stripGradleComments(body string) string {
	var out strings.Builder
	out.Grow(len(body))
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '/' && i+1 < len(body) && body[i+1] == '/':
			for i < len(body) && body[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(body) && body[i+1] == '*':
			i += 2
			for i < len(body) {
				if body[i] == '*' && i+1 < len(body) && body[i+1] == '/' {
					i += 2
					break
				}
				if body[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
		case (c == '\'' || c == '"') && i+2 < len(body) && body[i+1] == c && body[i+2] == c:
			quote := c
			i += 3
			for i < len(body) {
				if body[i] == quote && i+2 < len(body) && body[i+1] == quote && body[i+2] == quote {
					i += 3
					break
				}
				if body[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
		case c == '\'' || c == '"':
			quote := c
			out.WriteByte(c)
			i++
			for i < len(body) {
				if body[i] == '\\' && i+1 < len(body) {
					out.WriteByte(body[i])
					out.WriteByte(body[i+1])
					i += 2
					continue
				}
				out.WriteByte(body[i])
				if body[i] == quote {
					i++
					break
				}
				i++
			}
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// walkGradleSettingsModules reads the settings script in workingDir and
// returns every included subproject in project-path order. A build without a
// settings script (or with no includes) yields no modules and no error;
// composite builds (includeBuild) are not expanded. Included paths that
// resolve outside the build root are skipped.
func walkGradleSettingsModules(workingDir string) ([]gradleModule, error) {
	body, err := readGradleSettings(workingDir)
	if err != nil {
		return nil, fmt.Errorf("walk gradle settings modules: %w", err)
	}
	if body == "" {
		return nil, nil
	}
	body = stripGradleComments(body)

	overrides := map[string]string{}
	for _, match := range gradleProjectDirOverride.FindAllStringSubmatch(body, -1) {
		overrides[match[1]] = match[2]
	}
	rootGroup := readGradleGroupAssignment(workingDir)

	seen := map[string]struct{}{}
	var modules []gradleModule
	for _, projectPath := range gradleIncludedProjectPaths(body) {
		projectPath = strings.TrimSpace(projectPath)
		if projectPath == "" {
			continue
		}
		if !strings.HasPrefix(projectPath, ":") {
			projectPath = ":" + projectPath
		}
		if projectPath == ":" {
			continue
		}
		if _, ok := seen[projectPath]; ok {
			continue
		}
		seen[projectPath] = struct{}{}

		rel := overrides[projectPath]
		if rel == "" {
			rel = strings.ReplaceAll(strings.TrimPrefix(projectPath, ":"), ":", "/")
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		if rel == "." || rel == "" || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			continue
		}

		dir := filepath.Join(workingDir, filepath.FromSlash(rel))
		group := readGradleGroupAssignment(dir)
		if group == "" {
			group = rootGroup
		}
		segments := strings.Split(strings.TrimPrefix(projectPath, ":"), ":")
		modules = append(modules, gradleModule{
			ProjectPath:  projectPath,
			Dir:          rel,
			Name:         segments[len(segments)-1],
			Group:        group,
			ManifestFile: gradleModuleManifestFile(dir),
		})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].ProjectPath < modules[j].ProjectPath })
	disambiguateGradleModuleNames(modules)
	return modules, nil
}

func readGradleSettings(workingDir string) (string, error) {
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		raw, err := os.ReadFile(filepath.Join(workingDir, name))
		if err == nil {
			return string(raw), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
	}
	return "", nil
}

// gradleIncludedProjectPaths collects quoted project paths from both
// include forms: `include(":a", ":b")` and `include ':a', ':b'`.
func gradleIncludedProjectPaths(body string) []string {
	seen := map[string]struct{}{}
	var paths []string
	add := func(fragment string) {
		for _, quoted := range gradleQuotedValue.FindAllStringSubmatch(fragment, -1) {
			if _, ok := seen[quoted[1]]; ok {
				continue
			}
			seen[quoted[1]] = struct{}{}
			paths = append(paths, quoted[1])
		}
	}
	for _, include := range gradleParenthesizedInclude.FindAllStringSubmatch(body, -1) {
		add(include[1])
	}
	for _, include := range gradleLineInclude.FindAllStringSubmatch(body, -1) {
		add(include[1])
	}
	return paths
}

func readGradleGroupAssignment(dir string) string {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if match := gradleGroupAssignment.FindStringSubmatch(stripGradleComments(string(raw))); len(match) == 2 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func gradleModuleManifestFile(dir string) string {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return name
		}
	}
	return "build.gradle"
}

// disambiguateGradleModuleNames keeps the short project name (last path
// segment) unless two modules share it — nested layouts like :a:lib and
// :b:lib — in which case the full path form (a/lib) is used so the module
// root nodes get distinct identities.
func disambiguateGradleModuleNames(modules []gradleModule) {
	counts := map[string]int{}
	for _, module := range modules {
		counts[module.Name]++
	}
	for i := range modules {
		if counts[modules[i].Name] > 1 {
			modules[i].Name = strings.ReplaceAll(strings.TrimPrefix(modules[i].ProjectPath, ":"), ":", "/")
		}
	}
}
