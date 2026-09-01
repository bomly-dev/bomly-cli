package bun

import (
	"errors"
	"fmt"
	"github.com/bomly-dev/bomly-cli/internal/nodes"
	"path"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

func depGraphFromBunPMList(raw []byte, manifest node.PackageJSONManifest, projectDir string, logger *zap.Logger) (*sdk.Graph, error) {
	rootName := manifest.Name
	if rootName == "" {
		rootName = "root"
	}
	graph := sdk.New()
	root, err := bunRootModuleNode("package.json", rootName, manifest.Version)
	if err != nil {
		return nil, err
	}
	if err := graph.AddNode(root); err != nil {
		return nil, fmt.Errorf("add Bun project root: %w", err)
	}

	byName := make(map[string]map[string]sdk.GraphNode)
	parents := make([]string, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		name, version, depth, ok := parseBunPMListLine(line)
		if !ok {
			continue
		}
		dependency, err := bunPMListDependency(projectDir, manifest, name, version)
		if err != nil {
			return nil, err
		}
		if err := node.AddNodeIfMissing(graph, dependency); err != nil {
			return nil, err
		}
		stored, _ := graph.Node(dependency.NodeID())
		if byName[name] == nil {
			byName[name] = make(map[string]sdk.GraphNode)
		}
		byName[name][stored.NodeID()] = stored

		if depth > 0 && depth <= len(parents) && parents[depth-1] != stored.NodeID() {
			if err := graph.AddEdge(parents[depth-1], stored.NodeID()); err != nil {
				return nil, fmt.Errorf("attach nested Bun dependency %q -> %q: %w", parents[depth-1], stored.NodeID(), err)
			}
		}
		if len(parents) <= depth {
			parents = append(parents, make([]string, depth-len(parents)+1)...)
		}
		parents[depth] = stored.NodeID()
		parents = parents[:depth+1]

		// Ownership is the node kind now, not a Source value on a
		// dependency node (ADR-0041): a workspace member is a module.
		if stored.Kind() == sdk.NodeKindModule {
			if err := graph.AddEdge(root.NodeID(), stored.NodeID()); err != nil {
				return nil, fmt.Errorf("attach Bun workspace %q: %w", stored.NodeID(), err)
			}
		}
	}
	if graph.Size() == 1 {
		return nil, errors.New("bun pm ls returned no installed packages")
	}

	directScopes := node.DirectDependencyScopes(manifest)
	for name, scope := range directScopes {
		matches := byName[name]
		// A flat inventory cannot say which of several same-named nodes
		// carries the root declaration. Leave them all unscoped rather than
		// guessing.
		if len(matches) != 1 {
			continue
		}
		var match sdk.GraphNode
		for _, dependency := range matches {
			match = dependency
		}
		if dependency, ok := nodes.AsDependency(match); ok {
			dependency.AddScope(scope)
		}
		if err := graph.AddEdge(root.NodeID(), match.NodeID()); err != nil {
			return nil, fmt.Errorf("attach direct Bun dependency %q: %w", match.NodeID(), err)
		}
	}
	if _, err := node.AttachUnknownComponents(graph, root.NodeID(), logger, detectors.NameBunNative, "package.json"); err != nil {
		return nil, err
	}
	return graph, nil
}

// bunRootModuleNode builds the project's own node for a `bun pm ls` graph.
func bunRootModuleNode(manifestPath, name, version string) (*sdk.ModuleNode, error) {
	moduleNode, err := sdk.NewModuleNode(manifestPath, sdk.Coordinates{
		Ecosystem:      sdk.EcosystemNPM,
		PackageManager: sdk.PackageManagerBun,
		Name:           name,
		Version:        version,
		Type:           sdk.PackageTypeApplication,
	})
	if err != nil {
		return nil, fmt.Errorf("build Bun module node %q: %w", name, err)
	}
	return moduleNode, nil
}

func bunPMListDependency(projectDir string, manifest node.PackageJSONManifest, listedName, listedVersion string) (sdk.GraphNode, error) {
	source := node.DependencySourceFromSpecifier(listedVersion)
	name, version := listedName, listedVersion
	workspaceDir := ""
	if source == sdk.DependencySourceWorkspace {
		workspacePath := strings.TrimPrefix(listedVersion, "workspace:")
		workspace, err := node.ReadPackageJSONManifest(filepath.Join(projectDir, filepath.FromSlash(workspacePath)))
		if err == nil {
			if workspace.Name != "" {
				name = workspace.Name
			}
			version = workspace.Version
		} else {
			version = ""
		}
		workspaceDir = filepath.ToSlash(filepath.Clean(workspacePath))
	} else if requested, declared := declaredBunSpecifier(manifest, listedName); declared {
		// An npm alias ("foo": "npm:bar@1.2.3") is a declaration detail, not
		// a second package: the installed package is bar, and its identity is
		// bar's PURL. The alias no longer mints a separate ID -- two aliases
		// of one target fold to the one node they always described.
		actualName, _ := bunAliasTarget(listedName, requested)
		if actualName != listedName {
			name = actualName
		}
	}
	if source == sdk.DependencySourceWorkspace {
		return bunRootModuleNode(path.Join(workspaceDir, "package.json"), name, version)
	}

	dependency, err := sdk.NewDependencyNode(sdk.Coordinates{
		Ecosystem:      sdk.EcosystemNPM,
		PackageManager: sdk.PackageManagerBun,
		Name:           name,
		Version:        version,
		Type:           sdk.PackageTypePackage,
	})
	if err != nil {
		return nil, fmt.Errorf("build Bun dependency node %q: %w", name, err)
	}
	dependency.Source = source
	dependency.FoundBy = detectors.NameBunNative
	return dependency, nil
}

func declaredBunSpecifier(manifest node.PackageJSONManifest, name string) (string, bool) {
	for _, dependencies := range []map[string]string{manifest.Dependencies, manifest.OptionalDependencies, manifest.PeerDependencies, manifest.DevDependencies} {
		if requested, ok := dependencies[name]; ok {
			return requested, true
		}
	}
	return "", false
}

func parseBunPMListLine(line string) (string, string, int, bool) {
	line = strings.TrimRight(line, "\r\n")
	branch := strings.Index(line, "├── ")
	if branch < 0 {
		branch = strings.Index(line, "└── ")
	}
	if branch < 0 {
		return "", "", 0, false
	}
	prefix := []rune(line[:branch])
	if len(prefix)%4 != 0 {
		return "", "", 0, false
	}
	for offset := 0; offset < len(prefix); offset += 4 {
		group := string(prefix[offset : offset+4])
		if group != "│   " && group != "    " {
			return "", "", 0, false
		}
	}
	entry := strings.TrimSpace(line[branch+len("├── "):])
	separator := strings.LastIndex(entry, "@")
	if separator <= 0 || separator == len(entry)-1 {
		return "", "", 0, false
	}
	name, version := entry[:separator], entry[separator+1:]
	if strings.HasPrefix(name, "@") && !strings.Contains(name, "/") {
		return "", "", 0, false
	}
	if strings.ContainsAny(name, " \t\r\n") || strings.ContainsAny(version, " \t\r\n") {
		return "", "", 0, false
	}
	return name, version, len(prefix) / 4, true
}
