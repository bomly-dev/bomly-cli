package python

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	sdk "github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
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
	Git      string `toml:"git"`
	URL      string `toml:"url"`
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
	data, err := system.ReadRepositoryFile(uvLockPath)
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
	nodesByName := make(map[string]sdk.GraphNode, len(lock.Package))
	for i := range lock.Package {
		pkg := &lock.Package[i]
		if pkg.Name == "" {
			continue
		}
		node, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
			Name:    normalizePythonName(pkg.Name),
			Version: pkg.Version})
		if err != nil {
			return nil, fmt.Errorf("build dependency node: %w", err)
		}
		node.Source = uvDependencySource(pkg.Source)
		node.ResolvedURL = uvResolvedURL(pkg.Source)
		node.Metadata = sourceRevisionMetadata(uvSourceRevision(pkg.Source))
		setUVOrigin(node, pkg.Source)

		// A universal lock can hold several records for one package (marker
		// alternatives). References are by bare name, so one graph position
		// exists: the last record wins as a whole, deterministically -- no
		// field-level mixing between records.
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

	// The editable package is the scanned project itself, so it is a module
	// node: ownership is the node kind now, not a flag set on a dependency
	// after the fact (ADR-0041). It replaces the dependency node the index
	// built for it, so every reference by name resolves to the module.
	rootName := normalizePythonName(editablePkg.Name)
	if _, indexed := nodesByName[rootName]; !indexed {
		return nil, fmt.Errorf("uv.lock editable package %q not found in package index", editablePkg.Name)
	}
	rootNode, err := pythonModuleRoot(sdk.Coordinates{
		Ecosystem:      sdk.EcosystemPython,
		PackageManager: sdk.PackageManagerUV,
		Name:           rootName,
		Version:        editablePkg.Version,
		Type:           sdk.PackageTypeApplication,
	})
	if err != nil {
		return nil, fmt.Errorf("build root node: %w", err)
	}
	nodesByName[rootName] = rootNode
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
		if dependency, ok := sdk.AsDependencyNode(child); ok {
			dependency.AddScope(sdk.ScopeRuntime)
		}
		if err := depsGraph.AddEdge(rootNode.NodeID(), child.NodeID()); err != nil {
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
			if dependency, ok := sdk.AsDependencyNode(child); ok {
				dependency.AddScope(sdk.ScopeDevelopment)
			}
			if err := depsGraph.AddEdge(rootNode.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add dev dep %q: %w", dep.Name, err)
			}
		}
	}

	// Add transitive edges for all non-root packages and propagate scope.
	for i := range lock.Package {
		pkg := &lock.Package[i]
		parent := nodesByName[normalizePythonName(pkg.Name)]
		if parent == nil || parent.NodeID() == rootNode.NodeID() {
			continue
		}
		for _, dep := range pkg.Dependencies {
			if isExtrasRequirement(dep.Name) {
				continue
			}
			child := nodesByName[normalizePythonName(dep.Name)]
			if child == nil || child.NodeID() == rootNode.NodeID() {
				continue
			}
			if err := depsGraph.AddEdge(parent.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add dep %q -> %q: %w", pkg.Name, dep.Name, err)
			}
		}
	}

	// Runtime always beats development on any path that reaches a package.
	detectorkit.PropagateScopes(depsGraph, rootNode.NodeID(), nil)

	return depsGraph, nil
}

func uvDependencySource(source uvLockSource) sdk.DependencySource {
	switch {
	case source.Editable != "" || source.Path != "":
		return sdk.DependencySourceFile
	case source.Git != "":
		return sdk.DependencySourceGit
	case source.URL != "":
		return sdk.DependencySourceURL
	case source.Registry != "":
		return sdk.DependencySourceRegistry
	default:
		return ""
	}
}

func uvResolvedURL(source uvLockSource) string {
	for _, value := range []string{source.Git, source.URL, source.Registry, source.Editable, source.Path} {
		if value != "" {
			return value
		}
	}
	return ""
}

func uvSourceRevision(source uvLockSource) string {
	parsed, err := url.Parse(strings.TrimSpace(source.Git))
	if err != nil {
		return ""
	}
	if parsed.Fragment != "" {
		return parsed.Fragment
	}
	query := parsed.Query()
	for _, key := range []string{"rev", "tag", "branch"} {
		if value := strings.TrimSpace(query.Get(key)); value != "" {
			return value
		}
	}
	return ""
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
