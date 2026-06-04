package jvmreach

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

type jvmModule struct {
	Dir         string
	Coord       string
	Prefixes    []string
	Application bool
}

type moduleHierarchy struct {
	Root    string
	Modules []jvmModule
}

type mavenProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Parent     struct {
		GroupID string `xml:"groupId"`
	} `xml:"parent"`
	Modules []string `xml:"modules>module"`
}

var (
	gradleParenthesizedInclude = regexp.MustCompile(`(?s)\binclude\s*\((.*?)\)`)
	gradleLineInclude          = regexp.MustCompile(`(?m)^\s*include\s+([^\r\n]+)$`)
	gradleQuotedValue          = regexp.MustCompile(`["']([^"']+)["']`)
	gradleProjectDir           = regexp.MustCompile(`(?m)project\s*\(\s*["']([^"']+)["']\s*\)\.projectDir\s*=\s*file\s*\(\s*["']([^"']+)["']\s*\)`)
	gradleGroup                = regexp.MustCompile(`(?m)^\s*group\s*=\s*["']([^"']+)["']`)
	sourcePackage              = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)`)
)

// discoverProjectRoots returns the root of each JVM project hierarchy.
func discoverProjectRoots(req model.AnalyzeRequest) []string {
	hierarchies := discoverModuleHierarchies(req)
	roots := make([]string, 0, len(hierarchies))
	for _, hierarchy := range hierarchies {
		roots = append(roots, hierarchy.Root)
	}
	return roots
}

func discoverModuleHierarchies(req model.AnalyzeRequest) []moduleHierarchy {
	projectRoots := discoverStandaloneProjectRoots(req)
	seen := make(map[string]struct{})
	hierarchies := make([]moduleHierarchy, 0, len(projectRoots))
	for _, projectRoot := range projectRoots {
		root := findHierarchyRoot(projectRoot)
		if root == "" {
			root = projectRoot
		}
		root = filepath.Clean(root)
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		hierarchy := moduleHierarchy{Root: root, Modules: discoverHierarchyModules(root)}
		if len(hierarchy.Modules) == 0 {
			hierarchy.Modules = []jvmModule{{Dir: root}}
		}
		for i := range hierarchy.Modules {
			hierarchy.Modules[i].Prefixes = discoverSourcePrefixes(hierarchy.Modules[i].Dir)
			hierarchy.Modules[i].Application = moduleHasApplicationEntryPoint(hierarchy.Modules[i].Dir)
		}
		hierarchies = append(hierarchies, hierarchy)
	}
	sort.Slice(hierarchies, func(i, j int) bool { return hierarchies[i].Root < hierarchies[j].Root })
	return hierarchies
}

func discoverStandaloneProjectRoots(req model.AnalyzeRequest) []string {
	seen := make(map[string]struct{})
	var roots []string
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
			if pkg == nil || !isJVMPackage(pkg) {
				continue
			}
			for _, loc := range pkg.Locations {
				if root := findProjectRoot(loc.RealPath); root != "" {
					add(root)
				}
			}
		}
	}
	for _, candidate := range []string{req.ProjectPath, req.ExecutionTarget.Location} {
		if root := findProjectRoot(candidate); root != "" {
			add(root)
		}
	}
	sort.Strings(roots)
	return roots
}

func findHierarchyRoot(start string) string {
	dir := filepath.Clean(start)
	var found string
	for {
		if hasMavenModules(dir) || len(readGradleModules(dir)) > 0 {
			found = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return found
		}
		dir = parent
	}
}

func discoverHierarchyModules(root string) []jvmModule {
	seen := make(map[string]jvmModule)
	if _, err := os.Stat(filepath.Join(root, "pom.xml")); err == nil {
		discoverMavenModules(root, "", seen)
	}
	for _, module := range readGradleModules(root) {
		seen[module.Dir] = module
	}
	if len(seen) == 0 {
		seen[root] = jvmModule{Dir: root}
	} else if _, ok := seen[root]; !ok {
		seen[root] = jvmModule{Dir: root}
	}
	modules := make([]jvmModule, 0, len(seen))
	for _, module := range seen {
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Dir < modules[j].Dir })
	return modules
}

func discoverMavenModules(dir, inheritedGroup string, seen map[string]jvmModule) {
	project, ok := readMavenProject(dir)
	if !ok {
		return
	}
	group := strings.TrimSpace(project.GroupID)
	if group == "" {
		group = strings.TrimSpace(project.Parent.GroupID)
	}
	if group == "" {
		group = inheritedGroup
	}
	dir = filepath.Clean(dir)
	seen[dir] = jvmModule{Dir: dir, Coord: canonicalCoord(group, project.ArtifactID)}
	for _, child := range project.Modules {
		childDir := filepath.Clean(filepath.Join(dir, filepath.FromSlash(strings.TrimSpace(child))))
		if pathContainsRoot(childDir, dir) {
			discoverMavenModules(childDir, group, seen)
		}
	}
}

func readMavenProject(dir string) (mavenProject, bool) {
	var project mavenProject
	data, err := os.ReadFile(filepath.Join(dir, "pom.xml"))
	if err != nil || xml.Unmarshal(data, &project) != nil {
		return project, false
	}
	return project, true
}

func hasMavenModules(dir string) bool {
	project, ok := readMavenProject(dir)
	return ok && len(project.Modules) > 0
}

func readGradleModules(root string) []jvmModule {
	var settingsPath string
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			settingsPath = path
			break
		}
	}
	if settingsPath == "" {
		return nil
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil
	}
	body := string(data)
	overrides := make(map[string]string)
	for _, match := range gradleProjectDir.FindAllStringSubmatch(body, -1) {
		overrides[match[1]] = match[2]
	}
	group := readGradleGroup(root)
	seen := make(map[string]jvmModule)
	for _, projectPath := range gradleIncludedProjectPaths(body) {
		relative := overrides[projectPath]
		if relative == "" {
			relative = strings.ReplaceAll(strings.TrimPrefix(projectPath, ":"), ":", string(filepath.Separator))
		}
		dir := filepath.Clean(filepath.Join(root, relative))
		if !pathContainsRoot(dir, root) {
			continue
		}
		artifact := filepath.Base(dir)
		moduleGroup := readGradleGroup(dir)
		if moduleGroup == "" {
			moduleGroup = group
		}
		seen[dir] = jvmModule{Dir: dir, Coord: canonicalCoord(moduleGroup, artifact)}
	}
	modules := make([]jvmModule, 0, len(seen))
	for _, module := range seen {
		modules = append(modules, module)
	}
	return modules
}

func gradleIncludedProjectPaths(body string) []string {
	seen := make(map[string]struct{})
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

func readGradleGroup(dir string) string {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if match := gradleGroup.FindStringSubmatch(string(data)); len(match) == 2 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func discoverSourcePrefixes(root string) []string {
	seen := make(map[string]struct{})
	_, _ = walkSourceFiles(root, func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, match := range sourcePackage.FindAllStringSubmatch(string(data), -1) {
			seen[match[1]] = struct{}{}
		}
		return nil
	})
	prefixes := make([]string, 0, len(seen))
	for prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) == len(prefixes[j]) {
			return prefixes[i] < prefixes[j]
		}
		return len(prefixes[i]) > len(prefixes[j])
	})
	return prefixes
}

func moduleHasApplicationEntryPoint(root string) bool {
	found := false
	_, _ = walkSourceFiles(root, func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		body := string(data)
		if strings.Contains(body, "static void main(") ||
			strings.Contains(body, "fun main(") ||
			strings.Contains(body, "@SpringBootApplication") ||
			strings.Contains(body, " extends App") {
			found = true
		}
		return nil
	})
	return found
}

// findProjectRoot walks upward from start until it finds a directory
// that contains a recognised JVM project file. Returns "" when none is found.
func findProjectRoot(start string) string {
	dir := start
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if dir == "" {
			return ""
		}
		if hasProjectMarker(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isJVMPackage reports whether pkg's ecosystem, build system, or language identifies it as JVM.
func isJVMPackage(pkg *model.Dependency) bool {
	if pkg == nil {
		return false
	}
	switch strings.ToLower(pkg.Ecosystem) {
	case string(model.EcosystemMaven), string(model.EcosystemScala):
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.BuildSystem)) {
	case "maven", "gradle", "sbt":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(pkg.Language)) {
	case string(model.LanguageJava), string(model.LanguageKotlin), string(model.LanguageScala), string(model.LanguageGroovy):
		return true
	}
	return false
}
