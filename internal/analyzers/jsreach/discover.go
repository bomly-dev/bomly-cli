package jsreach

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"gopkg.in/yaml.v3"
)

type workspaceMember struct {
	Name string
	Dir  string
}

type workspaceHierarchy struct {
	Root    string
	Members []workspaceMember
}

// discoverProjectRoots returns the npm project roots (directories that
// contain a package.json) derivable from the request. The same three
// sources govulncheck uses for go modules apply here, in priority
// order:
//
//  1. Each npm package's PackageLocation.RealPath: walk upward to the
//     nearest directory containing a package.json that ALSO has a
//     lockfile or a top-level "name" / "main" / "exports". This filters
//     out package.json files inside nested node_modules.
//  2. Each ConsolidatedManifest's manifest path when the request
//     surface ever exposes that (not currently part of AnalyzeRequest;
//     kept here as a future extension hook).
//  3. The request's ProjectPath / ExecutionTarget.Location, when it
//     itself contains a package.json.
//
// Paths are normalized with filepath.Clean. Duplicates are removed and
// results are sorted for deterministic ordering.
func discoverProjectRoots(req model.AnalyzeRequest) []string {
	hierarchies := discoverWorkspaceHierarchies(req)
	roots := make([]string, 0, len(hierarchies))
	for _, hierarchy := range hierarchies {
		roots = append(roots, hierarchy.Root)
	}
	return roots
}

func discoverWorkspaceHierarchies(req model.AnalyzeRequest) []workspaceHierarchy {
	packageRoots := discoverPackageRoots(req)
	seen := make(map[string]struct{})
	hierarchies := make([]workspaceHierarchy, 0, len(packageRoots))
	for _, packageRoot := range packageRoots {
		root := findWorkspaceRoot(packageRoot)
		if root == "" {
			root = packageRoot
		}
		root = filepath.Clean(root)
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		members := discoverWorkspaceMembers(root)
		if len(members) == 0 {
			members = []workspaceMember{{Name: readPackageName(root), Dir: root}}
		}
		hierarchies = append(hierarchies, workspaceHierarchy{Root: root, Members: members})
	}
	sort.Slice(hierarchies, func(i, j int) bool { return hierarchies[i].Root < hierarchies[j].Root })
	return hierarchies
}

func discoverPackageRoots(req model.AnalyzeRequest) []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0)

	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		roots = append(roots, clean)
	}

	if req.Graph != nil {
		for _, pkg := range req.Graph.Nodes() {
			if pkg == nil || !isNPMPackage(pkg) {
				continue
			}
			for _, loc := range pkg.Locations {
				if loc.RealPath == "" {
					continue
				}
				if root := findPackageJSONRoot(loc.RealPath); root != "" {
					add(root)
				}
			}
		}
	}

	for _, candidate := range []string{req.ProjectPath, req.ExecutionTarget.Location} {
		if candidate == "" {
			continue
		}
		if root := findPackageJSONRoot(candidate); root != "" {
			add(root)
		}
	}

	sort.Strings(roots)
	return roots
}

func findWorkspaceRoot(start string) string {
	dir := filepath.Clean(start)
	var found string
	for {
		if len(readWorkspacePatterns(dir)) > 0 {
			found = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return found
		}
		dir = parent
	}
}

func discoverWorkspaceMembers(root string) []workspaceMember {
	members := make(map[string]workspaceMember)
	var queue []string
	add := func(dir string) {
		dir = filepath.Clean(dir)
		name := readPackageName(dir)
		if name == "" {
			return
		}
		if _, ok := members[dir]; ok {
			return
		}
		members[dir] = workspaceMember{Name: name, Dir: dir}
		queue = append(queue, dir)
	}
	add(root)
	for len(queue) > 0 {
		owner := queue[0]
		queue = queue[1:]
		patterns := readWorkspacePatterns(owner)
		if len(patterns) == 0 {
			continue
		}
		_ = filepath.WalkDir(owner, func(path string, entry os.DirEntry, err error) error {
			if err != nil || !entry.IsDir() {
				return nil
			}
			if path != owner && shouldSkipWorkspaceDir(entry.Name()) {
				return filepath.SkipDir
			}
			if path == owner {
				return nil
			}
			rel, err := filepath.Rel(owner, path)
			if err == nil && workspacePathIncluded(filepath.ToSlash(rel), patterns) {
				add(path)
			}
			return nil
		})
	}
	out := make([]workspaceMember, 0, len(members))
	for _, member := range members {
		out = append(out, member)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

func readWorkspacePatterns(dir string) []string {
	var patterns []string
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err == nil {
		var manifest struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if json.Unmarshal(data, &manifest) == nil {
			var list []string
			if json.Unmarshal(manifest.Workspaces, &list) == nil {
				patterns = append(patterns, list...)
			} else {
				var object struct {
					Packages []string `json:"packages"`
				}
				if json.Unmarshal(manifest.Workspaces, &object) == nil {
					patterns = append(patterns, object.Packages...)
				}
			}
		}
	}
	data, err = os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml"))
	if err == nil {
		var manifest struct {
			Packages []string `yaml:"packages"`
		}
		if yaml.Unmarshal(data, &manifest) == nil {
			patterns = append(patterns, manifest.Packages...)
		}
	}
	return patterns
}

func readPackageName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return ""
	}
	return strings.TrimSpace(manifest.Name)
}

func workspacePathIncluded(path string, patterns []string) bool {
	included := false
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		if pattern == "" || !workspaceGlobMatch(path, pattern) {
			continue
		}
		included = !negated
	}
	return included
}

func workspaceGlobMatch(path, pattern string) bool {
	var expression strings.Builder
	expression.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					expression.WriteString("(?:.*/)?")
					i++
				} else {
					expression.WriteString(".*")
				}
				i++
			} else {
				expression.WriteString("[^/]*")
			}
		case '?':
			expression.WriteString("[^/]")
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	expression.WriteString("$")
	matched, _ := regexp.MatchString(expression.String(), filepath.ToSlash(path))
	return matched
}

func shouldSkipWorkspaceDir(name string) bool {
	switch name {
	case "node_modules", ".git", ".hg", ".svn", "dist", "build", "coverage":
		return true
	}
	return false
}

// findPackageJSONRoot walks upward from start until it finds a
// directory whose package.json looks like an application root (i.e.
// not a package.json that lives inside node_modules — those describe
// individual packages, not project roots). Returns "" when none is
// found before reaching the filesystem root.
//
// We deliberately accept a package.json with no "main" / "module" /
// "exports" / "bin" — entry-point discovery handles the
// implicit-index.js fallback.
func findPackageJSONRoot(start string) string {
	dir := start
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if dir == "" {
			return ""
		}
		candidate := filepath.Join(dir, "package.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if !isInsideNodeModules(dir) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isInsideNodeModules reports whether the given directory is itself
// inside a node_modules tree. The npm publish-time package.json files
// installed under node_modules look identical to project roots; we
// must skip them to avoid analyzing a dependency as if it were the
// application.
func isInsideNodeModules(dir string) bool {
	normalized := filepath.ToSlash(dir)
	return strings.Contains(normalized, "/node_modules/") || strings.HasSuffix(normalized, "/node_modules")
}

// isNPMPackage reports whether pkg's ecosystem or build system
// identifies it as an npm package. Mirrors govulncheck.isGoPackage.
func isNPMPackage(pkg *model.Dependency) bool {
	if pkg == nil {
		return false
	}
	if pkg.Ecosystem == model.EcosystemNPM {
		return true
	}
	switch pkg.PackageManager {
	case model.PackageManagerNPM, model.PackageManagerPNPM, model.PackageManagerYarn:
		return true
	}
	switch pkg.Language {
	case model.LanguageJavaScript, model.LanguageTypeScript:
		return true
	}
	return false
}
