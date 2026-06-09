package python

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// uvLockDep is a dependency reference in uv.lock.
type uvLockDep struct {
	Name string `toml:"name"`
}

// uvLockSource holds the source fields of a [[package]] entry.
type uvLockSource struct {
	Registry string `toml:"registry"`
	Editable string `toml:"editable"`
	Path     string `toml:"path"`
}

// uvLockPackage represents a single [[package]] entry in uv.lock.
type uvLockPackage struct {
	Name    string       `toml:"name"`
	Version string       `toml:"version"`
	Source  uvLockSource `toml:"source"`

	// Runtime dependencies of this package.
	Dependencies []uvLockDep `toml:"dependencies"`

	// Dev-dependency groups (e.g. [package.dev-dependencies] dev = [...]).
	DevDependencies map[string][]uvLockDep `toml:"dev-dependencies"`
}

// uvLockFile is the top-level structure of a uv.lock file.
type uvLockFile struct {
	Package []uvLockPackage `toml:"package"`
}

// depGraphFromUVLock parses a uv.lock file and builds a dependency graph with
// proper runtime / development scope annotations.
func depGraphFromUVLock(uvLockPath string) (*sdk.Graph, error) {
	data, err := os.ReadFile(uvLockPath)
	if err != nil {
		return nil, fmt.Errorf("read uv.lock: %w", err)
	}

	var lock uvLockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("parse uv.lock: %w", err)
	}
	if len(lock.Package) == 0 {
		return nil, fmt.Errorf("uv.lock contains no packages")
	}

	// Index all packages by normalized name.
	nodesByName := make(map[string]*sdk.Dependency, len(lock.Package))
	for i := range lock.Package {
		pkg := &lock.Package[i]
		if pkg.Name == "" {
			continue
		}
		node := sdk.NewDependency(sdk.Dependency{
			Ecosystem: string(sdk.EcosystemPython),
			Name:      normalizePythonName(pkg.Name),
			Version:   pkg.Version,
		})

		nodesByName[normalizePythonName(pkg.Name)] = node
	}

	// Locate the editable (project) package — it acts as the root.
	var editablePkg *uvLockPackage
	for i := range lock.Package {
		if lock.Package[i].Source.Editable != "" || lock.Package[i].Source.Path != "" {
			editablePkg = &lock.Package[i]
			break
		}
	}
	if editablePkg == nil {
		return nil, fmt.Errorf("uv.lock has no editable package entry")
	}

	depsGraph := sdk.New()

	// The root node represents the editable project itself.
	rootNode := nodesByName[normalizePythonName(editablePkg.Name)]
	if rootNode == nil {
		return nil, fmt.Errorf("uv.lock editable package %q not found in package index", editablePkg.Name)
	}
	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// Add all other packages to the graph.
	for name, node := range nodesByName {
		if name == normalizePythonName(editablePkg.Name) {
			continue
		}
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	// Add runtime edges: root → each runtime dep.
	for _, dep := range editablePkg.Dependencies {
		child := nodesByName[normalizePythonName(dep.Name)]
		if child == nil {
			continue
		}
		child.AddScope(sdk.ScopeRuntime)
		if err := depsGraph.AddEdge(rootNode.ID, child.ID); err != nil {
			return nil, fmt.Errorf("add runtime dep %q: %w", dep.Name, err)
		}
	}

	// Add dev edges: root → each dev dep (for all groups).
	for _, groupDeps := range editablePkg.DevDependencies {
		for _, dep := range groupDeps {
			child := nodesByName[normalizePythonName(dep.Name)]
			if child == nil {
				continue
			}
			// Runtime wins if this package is also a runtime dep.
			child.AddScope(sdk.ScopeDevelopment)
			if err := depsGraph.AddEdge(rootNode.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dev dep %q: %w", dep.Name, err)
			}
		}
	}

	// Add transitive edges for all non-root packages and propagate scope.
	for i := range lock.Package {
		pkg := &lock.Package[i]
		parent := nodesByName[normalizePythonName(pkg.Name)]
		if parent == nil || parent.ID == rootNode.ID {
			continue
		}
		for _, dep := range pkg.Dependencies {
			if isExtrasRequirement(dep.Name) {
				continue
			}
			child := nodesByName[normalizePythonName(dep.Name)]
			if child == nil || child.ID == rootNode.ID {
				continue
			}
			if err := depsGraph.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dep %q -> %q: %w", parent.Name, dep.Name, err)
			}
		}
	}

	// BFS to propagate scope from root's direct deps into the transitive tree.
	// Runtime always wins over development.
	directDeps, err := depsGraph.DirectDependencies(rootNode.ID)
	if err != nil || len(directDeps) == 0 {
		return depsGraph, nil
	}

	propagated := make(map[string]sdk.Scope, depsGraph.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.ID] = scope
		queue = append(queue, dep)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := depsGraph.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == rootNode.ID {
				continue
			}
			nextScope := sdk.MergeScope(propagated[child.ID], scope)
			if nextScope == propagated[child.ID] && child.PrimaryScope() == nextScope {
				continue
			}
			propagated[child.ID] = nextScope
			child.AddScope(nextScope)
			queue = append(queue, child)
		}
	}

	// Any unscoped non-root package defaults to runtime.
	for _, pkg := range depsGraph.Nodes() {
		if pkg != nil && pkg.ID != rootNode.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}

	return depsGraph, nil
}

// uvLockPath returns the path to the uv.lock file in the project directory,
// or an empty string if it does not exist.
func uvLockFilePath(projectPath string) string {
	p := filepath.Join(projectPath, "uv.lock")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
