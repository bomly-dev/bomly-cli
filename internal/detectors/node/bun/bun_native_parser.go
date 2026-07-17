package bun

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func depGraphFromBunPMList(raw []byte, manifest node.PackageJSONManifest, projectDir string, logger *zap.Logger) (*sdk.Graph, error) {
	rootName := manifest.Name
	if rootName == "" {
		rootName = "root"
	}
	graph := sdk.New()
	root := bunApplicationNode(rootName, manifest.Version, sdk.DependencySourceProject, "")
	if err := graph.AddNode(root); err != nil {
		return nil, fmt.Errorf("add Bun project root: %w", err)
	}

	byName := make(map[string]map[string]*sdk.Dependency)
	parents := make([]string, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		name, version, depth, ok := parseBunPMListLine(line)
		if !ok {
			continue
		}
		dependency := bunPMListDependency(projectDir, manifest, name, version)
		if err := node.AddNodeIfMissing(graph, dependency); err != nil {
			return nil, err
		}
		stored, _ := graph.Node(dependency.ID)
		if byName[name] == nil {
			byName[name] = make(map[string]*sdk.Dependency)
		}
		byName[name][stored.ID] = stored

		if depth > 0 && depth <= len(parents) && parents[depth-1] != stored.ID {
			if err := graph.AddEdge(parents[depth-1], stored.ID); err != nil {
				return nil, fmt.Errorf("attach nested Bun dependency %q -> %q: %w", parents[depth-1], stored.ID, err)
			}
		}
		if len(parents) <= depth {
			parents = append(parents, make([]string, depth-len(parents)+1)...)
		}
		parents[depth] = stored.ID
		parents = parents[:depth+1]

		if stored.Source == sdk.DependencySourceWorkspace {
			if err := graph.AddEdge(root.ID, stored.ID); err != nil {
				return nil, fmt.Errorf("attach Bun workspace %q: %w", stored.ID, err)
			}
		}
	}
	if graph.Size() == 1 {
		return nil, errors.New("bun pm ls returned no installed packages")
	}

	directScopes := node.DirectDependencyScopes(manifest)
	for name, scope := range directScopes {
		matches := byName[name]
		// A flat inventory cannot identify which duplicate occurrence is the
		// root declaration. Keep every occurrence unknown instead of guessing.
		if len(matches) != 1 {
			continue
		}
		var match *sdk.Dependency
		for _, dependency := range matches {
			match = dependency
		}
		match.AddScope(scope)
		if err := graph.AddEdge(root.ID, match.ID); err != nil {
			return nil, fmt.Errorf("attach direct Bun dependency %q: %w", match.ID, err)
		}
	}
	if _, err := node.AttachUnknownComponents(graph, root.ID, logger, detectors.NameBunNative, "package.json"); err != nil {
		return nil, err
	}
	return graph, nil
}

func bunPMListDependency(projectDir string, manifest node.PackageJSONManifest, listedName, listedVersion string) *sdk.Dependency {
	source := node.DependencySourceFromSpecifier(listedVersion)
	name, version := listedName, listedVersion
	forcedID := ""
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
		forcedID = "workspace:" + filepath.ToSlash(filepath.Clean(workspacePath))
	} else if requested, declared := declaredBunSpecifier(manifest, listedName); declared {
		actualName, _ := bunAliasTarget(listedName, requested)
		if actualName != listedName {
			name = actualName
			forcedID = "bun-native-alias:" + listedName + "@" + listedVersion
		}
	}

	dependency := sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem:      sdk.EcosystemNPM,
		PackageManager: sdk.PackageManagerBun,
		Name:           name,
		Version:        version,
		Type:           sdk.PackageTypePackage,
	}, Source: source, FoundBy: detectors.NameBunNative}
	if source == sdk.DependencySourceWorkspace {
		dependency.Type = sdk.PackageTypeApplication
	}
	if forcedID != "" {
		return sdk.NewDependencyWithID(forcedID, dependency)
	}
	return sdk.NewDependency(dependency)
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
