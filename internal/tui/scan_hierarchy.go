package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
)

// manifestTreeGroup is one subproject or module grouping of manifest rows in
// the scan trees. Kind follows the output hierarchy terminology: a
// "subproject" is an independently discovered nested directory, a "module"
// is a workspace/reactor member resolved under one root manifest.
type manifestTreeGroup struct {
	kind      output.ManifestNodeKind
	dir       string
	label     string
	manifests []int                // indexes into ScanModel.manifests
	children  []*manifestTreeGroup // module groups nested under a subproject
	// attachedTo is the index (into ScanModel.manifests) of the parent-level
	// manifest that natively resolves this module (the workspace lockfile or
	// reactor pom), or -1 when no unambiguous parent manifest exists. Views
	// nest attached modules under that manifest's node.
	attachedTo int
}

// key returns the stable expansion key for the group node.
func (g *manifestTreeGroup) key() string {
	return string(g.kind) + ":" + g.dir
}

// manifestCount returns the number of manifests in the group subtree.
func (g *manifestTreeGroup) manifestCount() int {
	count := len(g.manifests)
	for _, child := range g.children {
		count += child.manifestCount()
	}
	return count
}

// manifestTreeGroups derives the grouped view of the scan manifests:
// indexes of manifests attached directly to the project root plus ordered
// subproject/module group nodes (modules first, then subprojects, sorted by
// directory). Both slices are empty of groups for flat single-root scans,
// letting the trees keep their compact shape.
func (m *ScanModel) manifestTreeGroups() (rootManifests []int, groups []*manifestTreeGroup) {
	subprojects := map[string]*manifestTreeGroup{}
	modules := map[string]map[string]*manifestTreeGroup{} // parent dir → module dir → group

	attachModule := func(parentDir, moduleDir string, index int) {
		byDir, ok := modules[parentDir]
		if !ok {
			byDir = map[string]*manifestTreeGroup{}
			modules[parentDir] = byDir
		}
		group, ok := byDir[moduleDir]
		if !ok {
			label := moduleDir
			if parentDir != "." {
				label = strings.TrimPrefix(moduleDir, parentDir+"/")
			}
			group = &manifestTreeGroup{kind: output.ManifestNodeModule, dir: moduleDir, label: label, attachedTo: -1}
			byDir[moduleDir] = group
		}
		group.manifests = append(group.manifests, index)
	}

	for i, manifest := range m.manifests {
		subprojectDir, moduleDir := output.ClassifyManifest(manifest.relativePath, manifest.id)
		if subprojectDir == "." {
			if moduleDir == "" {
				rootManifests = append(rootManifests, i)
			} else {
				attachModule(".", moduleDir, i)
			}
			continue
		}
		group, ok := subprojects[subprojectDir]
		if !ok {
			group = &manifestTreeGroup{kind: output.ManifestNodeSubproject, dir: subprojectDir, label: subprojectDir, attachedTo: -1}
			subprojects[subprojectDir] = group
		}
		if moduleDir == "" {
			group.manifests = append(group.manifests, i)
		} else {
			attachModule(subprojectDir, moduleDir, i)
		}
	}

	sortedModules := func(parentDir string) []*manifestTreeGroup {
		byDir := modules[parentDir]
		dirs := make([]string, 0, len(byDir))
		for dir := range byDir {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		out := make([]*manifestTreeGroup, 0, len(dirs))
		for _, dir := range dirs {
			out = append(out, byDir[dir])
		}
		return out
	}

	// attachModules resolves which parent-level manifest natively produced
	// each module (matched by package-manager label, then ecosystem, then a
	// sole parent manifest), mirroring output.BuildHierarchy.
	attachModules := func(moduleGroups []*manifestTreeGroup, parentManifests []int) {
		for _, group := range moduleGroups {
			if group.kind != output.ManifestNodeModule || len(group.manifests) == 0 {
				continue
			}
			moduleManifest := m.manifests[group.manifests[0]]
			byManager := make([]int, 0, 1)
			byEcosystem := make([]int, 0, 1)
			for _, index := range parentManifests {
				if m.manifests[index].packageManagers == moduleManifest.packageManagers {
					byManager = append(byManager, index)
				}
				if m.manifests[index].ecosystem == moduleManifest.ecosystem {
					byEcosystem = append(byEcosystem, index)
				}
			}
			switch {
			case len(byManager) == 1:
				group.attachedTo = byManager[0]
			case len(byEcosystem) == 1:
				group.attachedTo = byEcosystem[0]
			case len(parentManifests) == 1:
				group.attachedTo = parentManifests[0]
			}
		}
	}

	groups = sortedModules(".")
	attachModules(groups, rootManifests)
	subprojectDirs := make([]string, 0, len(subprojects))
	for dir := range subprojects {
		subprojectDirs = append(subprojectDirs, dir)
	}
	sort.Strings(subprojectDirs)
	for _, dir := range subprojectDirs {
		group := subprojects[dir]
		group.children = sortedModules(dir)
		attachModules(group.children, group.manifests)
		groups = append(groups, group)
	}
	return rootManifests, groups
}

// treeLevelPrefix renders the continuation glyphs for every ancestor level of
// a tree item: "│  " while an ancestor has later siblings, "   " once it was
// the last child at its level.
func treeLevelPrefix(ancestorsLast []bool) string {
	var b strings.Builder
	for _, last := range ancestorsLast {
		if last {
			b.WriteString("   ")
		} else {
			b.WriteString("│  ")
		}
	}
	return b.String()
}

// treeConnector returns the branch glyph for an item given whether it is the
// last child at its level.
func treeConnector(last bool) string {
	if last {
		return "└─ "
	}
	return "├─ "
}

// groupDetails renders the details pane for a subproject or module node.
func (m *ScanModel) groupDetails(group *manifestTreeGroup, componentCount int) []string {
	title := "Subproject"
	description := "An independently discovered nested project under the scan root."
	if group.kind == output.ManifestNodeModule {
		title = "Module"
		description = "A workspace/reactor member resolved by its package manager under one root manifest."
	}
	ecosystems := map[string]struct{}{}
	managers := map[string]struct{}{}
	for _, index := range group.manifests {
		manifest := m.manifests[index]
		if manifest.ecosystem != "" {
			ecosystems[manifest.ecosystem] = struct{}{}
		}
		if manifest.packageManagers != "" {
			managers[manifest.packageManagers] = struct{}{}
		}
	}
	lines := []string{
		render.Style(title, render.Bold, render.Cyan),
		"",
		render.Style("  Directory: ", render.Dim) + group.dir,
		render.Style("  Ecosystems: ", render.Dim) + valueOrDash(sortedKeyList(ecosystems)),
		render.Style("  Package managers: ", render.Dim) + valueOrDash(sortedKeyList(managers)),
		render.Style("  Manifests: ", render.Dim) + fmt.Sprintf("%d", group.manifestCount()),
	}
	if len(group.children) > 0 {
		lines = append(lines, render.Style("  Modules: ", render.Dim)+fmt.Sprintf("%d", len(group.children)))
	}
	lines = append(lines,
		render.Style("  Components: ", render.Dim)+fmt.Sprintf("%d", componentCount),
		"",
		render.Style(description, render.Dim),
	)
	return lines
}

// manifestModuleDir returns the module directory of a manifest row, or ""
// when the manifest sits directly in its subproject directory.
func manifestModuleDir(row listPackageRow) string {
	_, moduleDir := output.ClassifyManifest(row.relativePath, row.id)
	return moduleDir
}

// manifestRootName returns the package name of a manifest's graph root — the
// project/module's own name (web, core-lib) — falling back to the manifest
// file name when the root carries no name.
func (m *ScanModel) manifestRootName(manifest listPackageRow) string {
	if m.graphValue != nil && manifest.rootID != "" {
		if pkg, ok := m.graphValue.Node(manifest.rootID); ok && pkg != nil && strings.TrimSpace(pkg.Name) != "" {
			return pkg.Name
		}
	}
	return manifest.displayName
}

// mergedGroupDetails renders the details pane for a merged project/module
// node: the node identity (a subproject or module and its manifest are two
// faces of the same thing), followed by the full manifest, detector, and
// dependency sections.
func (m *ScanModel) mergedGroupDetails(group *manifestTreeGroup, manifest listPackageRow, componentCount int) []string {
	title := "Subproject"
	description := "An independently discovered nested project under the scan root."
	if group.kind == output.ManifestNodeModule {
		title = "Module"
		description = "A workspace/reactor member resolved by its package manager under one root manifest."
	}
	lines := []string{
		render.Style(title, render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + m.manifestRootName(manifest),
		render.Style("  Directory: ", render.Dim) + group.dir,
		render.Style("  Components: ", render.Dim) + fmt.Sprintf("%d", componentCount),
		render.Style("  "+description, render.Dim),
		"",
	}
	return append(lines, manifestDetails(m.graphValue, manifest)...)
}

// rootNodeDetails renders the details pane for the merged project's ROOT
// component row: the root component itself, the root manifest it stands on,
// and the module nodes branching out of it.
func (m *ScanModel) rootNodeDetails(row listPackageRow, manifest listPackageRow, attached []*manifestTreeGroup) []string {
	lines := componentDetails(m.graphValue, m.registry, row, manifest)
	lines = append(lines, "")
	lines = append(lines, manifestDetails(m.graphValue, manifest)...)
	if len(attached) > 0 {
		lines = append(lines, "", render.Style("Modules", render.Bold, render.Cyan))
		for _, group := range attached {
			name := group.label
			suffix := ""
			if len(group.manifests) > 0 {
				moduleManifest := m.manifests[group.manifests[0]]
				if rootName := m.manifestRootName(moduleManifest); rootName != "" && rootName != moduleManifest.displayName {
					name = rootName
				}
				suffix = " [" + moduleManifest.id + "]"
			}
			lines = append(lines, render.Style("  ", render.Dim)+name+render.Style(suffix, render.Dim))
		}
	}
	return lines
}

func sortedKeyList(values map[string]struct{}) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
