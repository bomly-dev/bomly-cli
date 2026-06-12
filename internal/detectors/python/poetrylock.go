package python

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// poetryLockPackage represents a single [[package]] entry in poetry.lock.
type poetryLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	// Groups lists the dependency groups this package belongs to.
	// "main" → runtime; anything else (dev, test, …) → development.
	Groups []string `toml:"groups"`
	// Dependencies lists this package's own dependencies (transitive edges).
	// Values are ignored — only the keys (dep names) matter.
	// map[string]any handles both `pytz = "*"` (string) and
	// `django = {version = "...", optional = true}` (inline table) shapes.
	Dependencies map[string]any `toml:"dependencies"`
}

// poetryLockFile is the top-level structure of a poetry.lock file.
type poetryLockFile struct {
	Package []poetryLockPackage `toml:"package"`
}

// poetryLockFilePath returns the path to poetry.lock if it exists inside
// projectPath, or an empty string if it does not.
func poetryLockFilePath(projectPath string) string {
	p := filepath.Join(projectPath, "poetry.lock")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// depGraphFromPoetryLock parses a poetry.lock TOML file and builds a
// dependency graph with proper transitive edges and runtime/development scope.
//
// Scope assignment:
//   - Packages whose "groups" field contains "main" → ScopeRuntime
//   - All other groups (dev, test, …)               → ScopeDevelopment
//
// BFS propagation ensures that a package reachable via a runtime path is
// always marked runtime even if it is also listed in a dev group.
func depGraphFromPoetryLock(lockPath, projectPath string) (*sdk.Graph, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}

	var lock poetryLockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}
	if len(lock.Package) == 0 {
		return nil, fmt.Errorf("poetry.lock contains no packages")
	}

	// Collect direct deps and root identity from pyproject.toml.
	mainDeps, devDeps, rootName, rootVersion := collectPoetryDepsAndRoot(projectPath)

	// Build a name-indexed map of sdk.Dependency nodes; assign initial scope from groups.
	nodesByName := make(map[string]*sdk.Dependency, len(lock.Package))
	for i := range lock.Package {
		pkg := &lock.Package[i]
		if pkg.Name == "" {
			continue
		}
		node := sdk.NewDependency(sdk.Dependency{
			Ecosystem:      sdk.EcosystemPython,
			Name:           normalizePythonName(pkg.Name),
			Version:        pkg.Version,
			PackageManager: sdk.PackageManagerPoetry,
			Language:       "python",
			Type:           sdk.PackageTypePackage,
			PURL:           sdk.BuildPackageURL("pypi", "", pkg.Name, pkg.Version),
		})

		for _, group := range pkg.Groups {
			if group == "main" {
				node.AddScope(sdk.ScopeRuntime)
			} else {
				node.AddScope(sdk.ScopeDevelopment)
			}
		}
		nodesByName[normalizePythonName(pkg.Name)] = node
	}

	// Build the graph.
	g := sdk.New()

	root := sdk.NewDependency(sdk.Dependency{
		Ecosystem:      sdk.EcosystemPython,
		Name:           rootName,
		Version:        rootVersion,
		PackageManager: sdk.PackageManagerPoetry,
		Language:       "python",
		Type:           sdk.PackageTypeApplication,
	})

	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// Add all dependency nodes.
	for _, node := range nodesByName {
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}

	// Wire root → direct runtime deps.
	for name := range mainDeps {
		node := nodesByName[normalizePythonName(name)]
		if node == nil {
			continue
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("wire root→%s: %w", name, err)
		}
	}

	// Wire root → direct dev deps.
	for name := range devDeps {
		node := nodesByName[normalizePythonName(name)]
		if node == nil {
			continue
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("wire root→%s (dev): %w", name, err)
		}
	}

	// Wire package → transitive dependency edges from [package.dependencies].
	for i := range lock.Package {
		pkg := &lock.Package[i]
		parent := nodesByName[normalizePythonName(pkg.Name)]
		if parent == nil {
			continue
		}
		for depName := range pkg.Dependencies {
			child := nodesByName[normalizePythonName(depName)]
			if child == nil || child.ID == root.ID || child.ID == parent.ID {
				continue
			}
			// Ignore duplicate-edge errors — AddDependency is idempotent for them.
			_ = g.AddEdge(parent.ID, child.ID)
		}
	}

	// Connect orphan packages (no incoming edges other than from themselves)
	// directly to root to preserve the single-root graph invariant.
	for _, node := range nodesByName {
		if node == nil || node.ID == root.ID {
			continue
		}
		dependents, _ := g.Dependents(node.ID)
		if len(dependents) == 0 {
			_ = g.AddEdge(root.ID, node.ID)
		}
	}

	// BFS scope propagation: runtime always beats development.
	directDeps, _ := g.DirectDependencies(root.ID)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.ID] = sdk.MergeScope(propagated[dep.ID], scope)
		dep.AddScope(propagated[dep.ID])
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == root.ID {
				continue
			}
			next := sdk.MergeScope(propagated[child.ID], scope)
			if next == propagated[child.ID] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.ID] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}

	// Any remaining unscoped non-root packages default to runtime.
	for _, pkg := range g.Nodes() {
		if pkg != nil && pkg.ID != root.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}

	return g, nil
}

// collectPoetryDepsAndRoot reads pyproject.toml and returns the direct
// runtime/dev dependency names and the project's root name/version.
//
// Handles Poetry 1.x ([tool.poetry.dependencies], [tool.poetry.group.*]) and
// PEP 735 / Poetry 2.x ([dependency-groups]) layouts.
func collectPoetryDepsAndRoot(projectPath string) (mainDeps, devDeps map[string]bool, rootName, rootVersion string) {
	mainDeps = make(map[string]bool)
	devDeps = make(map[string]bool)
	rootName = "root"
	rootVersion = ""

	raw, err := os.ReadFile(filepath.Join(projectPath, "pyproject.toml"))
	if err != nil {
		return
	}

	var doc map[string]any
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return
	}

	// [tool.poetry]
	tool, _ := doc["tool"].(map[string]any)
	poetry, _ := tool["poetry"].(map[string]any)
	if poetry != nil {
		if name, ok := poetry["name"].(string); ok && strings.TrimSpace(name) != "" {
			rootName = strings.TrimSpace(name)
		}
		if version, ok := poetry["version"].(string); ok {
			rootVersion = strings.TrimSpace(version)
		}
		// [tool.poetry.dependencies] → main (exclude the "python" version marker)
		if deps, ok := poetry["dependencies"].(map[string]any); ok {
			for name := range deps {
				if strings.ToLower(name) == "python" {
					continue
				}
				mainDeps[normalizePythonName(name)] = true
			}
		}
		// [tool.poetry.group.*.dependencies] → dev
		if groups, ok := poetry["group"].(map[string]any); ok {
			for _, groupVal := range groups {
				groupMap, _ := groupVal.(map[string]any)
				if deps, ok := groupMap["dependencies"].(map[string]any); ok {
					for name := range deps {
						devDeps[normalizePythonName(name)] = true
					}
				}
			}
		}
		// Legacy [tool.poetry.dev-dependencies]
		if deps, ok := poetry["dev-dependencies"].(map[string]any); ok {
			for name := range deps {
				devDeps[normalizePythonName(name)] = true
			}
		}
	}

	// [dependency-groups] (PEP 735 / Poetry 2.x)
	if depGroups, ok := doc["dependency-groups"].(map[string]any); ok {
		for _, items := range depGroups {
			arr, _ := items.([]any)
			for _, item := range arr {
				s, ok := item.(string)
				if !ok {
					continue
				}
				name := requirementName(s)
				if name != "" {
					devDeps[normalizePythonName(name)] = true
				}
			}
		}
	}

	return
}
