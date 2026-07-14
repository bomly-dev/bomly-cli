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
			group = &manifestTreeGroup{kind: output.ManifestNodeModule, dir: moduleDir, label: label}
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
			group = &manifestTreeGroup{kind: output.ManifestNodeSubproject, dir: subprojectDir, label: subprojectDir}
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

	groups = sortedModules(".")
	subprojectDirs := make([]string, 0, len(subprojects))
	for dir := range subprojects {
		subprojectDirs = append(subprojectDirs, dir)
	}
	sort.Strings(subprojectDirs)
	for _, dir := range subprojectDirs {
		group := subprojects[dir]
		group.children = sortedModules(dir)
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

func sortedKeyList(values map[string]struct{}) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
