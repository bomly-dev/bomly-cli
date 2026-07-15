package output

import (
	"path"
	"sort"
	"strings"
)

// ManifestNodeKind labels one level of the derived project hierarchy.
type ManifestNodeKind string

const (
	// ManifestNodeProject is the scan root.
	ManifestNodeProject ManifestNodeKind = "project"
	// ManifestNodeSubproject is an independently discovered nested directory
	// (a subproject planned by discovery with a non-root relative path).
	ManifestNodeSubproject ManifestNodeKind = "subproject"
	// ManifestNodeModule is a member the package manager natively resolves
	// under one root manifest (a Maven reactor module, an npm/pnpm/cargo
	// workspace member): its manifest path sits beneath the subproject
	// directory that produced it.
	ManifestNodeModule ManifestNodeKind = "module"
)

// HierarchyNode is one node of the derived project → subproject → module
// grouping of scan manifests. The hierarchy is a pure presentation view:
// it is derived from each manifest's Subproject and Path fields, never
// stored, so every consumer (TUI, text, markdown, MCP) shows the same
// structure without schema changes.
type HierarchyNode struct {
	Kind ManifestNodeKind
	// Dir is the repo-relative directory of the node; "." for the project root.
	Dir string
	// Label is the display name: subproject labels are their repo-relative
	// directory, module labels are relative to their parent node's directory.
	Label string
	// ManifestIndexes point into the manifests slice passed to BuildHierarchy
	// for manifests attached directly to this node, preserving input order.
	ManifestIndexes []int
	// Children holds module nodes (under project or subproject nodes) and
	// subproject nodes (under the project node only), modules first, each
	// group sorted by Dir.
	Children []HierarchyNode
	// AttachedManifest is set on module nodes only: the index (into the
	// manifests slice passed to BuildHierarchy) of the parent node's manifest
	// that natively resolves this module — the workspace lockfile or reactor
	// pom. -1 when no unambiguous parent manifest exists. Views nest modules
	// under that manifest's node.
	AttachedManifest int
}

// HasGroups reports whether the hierarchy contains any subproject or module
// nodes. Consumers keep today's flat presentation when it does not.
func (n HierarchyNode) HasGroups() bool {
	return len(n.Children) > 0
}

// CountKind returns the number of descendant nodes of the given kind.
func (n HierarchyNode) CountKind(kind ManifestNodeKind) int {
	count := 0
	for _, child := range n.Children {
		if child.Kind == kind {
			count++
		}
		count += child.CountKind(kind)
	}
	return count
}

// ClassifyManifest resolves where a manifest belongs in the hierarchy from
// its subproject relative path ("", "." = scan root) and its repo-relative
// manifest path. It returns the normalized subproject directory ("." for
// root) and the module directory: "" when the manifest sits directly in its
// subproject directory, otherwise the repo-relative directory of the module
// that owns the manifest. A manifest whose directory is not beneath its
// subproject directory attaches directly to the subproject (defensive).
func ClassifyManifest(subprojectRel, manifestPath string) (subprojectDir, moduleDir string) {
	subprojectDir = normalizeHierarchyDir(subprojectRel)
	manifestDir := path.Dir(normalizeHierarchyDir(manifestPath))
	if manifestDir == subprojectDir {
		return subprojectDir, ""
	}
	if hasHiddenPathSegment(manifestDir) {
		// Manifests inside dot-directories (.github/workflows/ci.yml) belong
		// to the node itself — hidden directories are metadata locations, not
		// modules.
		return subprojectDir, ""
	}
	if subprojectDir == "." {
		if manifestDir != "." && manifestDir != "" {
			return subprojectDir, manifestDir
		}
		return subprojectDir, ""
	}
	if strings.HasPrefix(manifestDir, subprojectDir+"/") {
		return subprojectDir, manifestDir
	}
	return subprojectDir, ""
}

// hasHiddenPathSegment reports whether any segment of a slash path starts
// with a dot.
func hasHiddenPathSegment(dir string) bool {
	for _, segment := range strings.Split(dir, "/") {
		if strings.HasPrefix(segment, ".") && segment != "." && segment != ".." {
			return true
		}
	}
	return false
}

// BuildHierarchy groups scan manifests into the derived project hierarchy:
// root-level manifests attach directly to the project node; module nodes and
// subproject nodes are its children (modules first, then subprojects, each
// sorted by directory); a subproject's own manifests attach to its node with
// its modules as children.
func BuildHierarchy(manifests []ScanManifest) HierarchyNode {
	root := HierarchyNode{Kind: ManifestNodeProject, Dir: ".", Label: ".", AttachedManifest: -1}
	subprojects := map[string]*HierarchyNode{}
	modules := map[string]map[string]*HierarchyNode{} // parent dir → module dir → node

	attachModule := func(parentDir, moduleDir string, index int) {
		byDir, ok := modules[parentDir]
		if !ok {
			byDir = map[string]*HierarchyNode{}
			modules[parentDir] = byDir
		}
		node, ok := byDir[moduleDir]
		if !ok {
			label := moduleDir
			if parentDir != "." {
				label = strings.TrimPrefix(moduleDir, parentDir+"/")
			}
			node = &HierarchyNode{Kind: ManifestNodeModule, Dir: moduleDir, Label: label, AttachedManifest: -1}
			byDir[moduleDir] = node
		}
		node.ManifestIndexes = append(node.ManifestIndexes, index)
	}

	for i, manifest := range manifests {
		subprojectDir, moduleDir := ClassifyManifest(manifest.Subproject, manifest.Path)
		if subprojectDir == "." {
			if moduleDir == "" {
				root.ManifestIndexes = append(root.ManifestIndexes, i)
			} else {
				attachModule(".", moduleDir, i)
			}
			continue
		}
		node, ok := subprojects[subprojectDir]
		if !ok {
			node = &HierarchyNode{Kind: ManifestNodeSubproject, Dir: subprojectDir, Label: subprojectDir, AttachedManifest: -1}
			subprojects[subprojectDir] = node
		}
		if moduleDir == "" {
			node.ManifestIndexes = append(node.ManifestIndexes, i)
		} else {
			attachModule(subprojectDir, moduleDir, i)
		}
	}

	// attachedManifestFor resolves which of the parent node's manifests
	// natively produced a module: the manifest with the module's package
	// manager (falling back to ecosystem, then to a sole parent manifest).
	attachedManifestFor := func(parentManifests []int, module *HierarchyNode) int {
		if len(module.ManifestIndexes) == 0 {
			return -1
		}
		moduleManifest := manifests[module.ManifestIndexes[0]]
		byManager := make([]int, 0, 1)
		byEcosystem := make([]int, 0, 1)
		for _, index := range parentManifests {
			if manifests[index].PackageManager == moduleManifest.PackageManager {
				byManager = append(byManager, index)
			}
			if manifests[index].Ecosystem == moduleManifest.Ecosystem {
				byEcosystem = append(byEcosystem, index)
			}
		}
		switch {
		case len(byManager) == 1:
			return byManager[0]
		case len(byEcosystem) == 1:
			return byEcosystem[0]
		case len(parentManifests) == 1:
			return parentManifests[0]
		default:
			return -1
		}
	}

	childModules := func(parentDir string, parentManifests []int) []HierarchyNode {
		byDir := modules[parentDir]
		dirs := make([]string, 0, len(byDir))
		for dir := range byDir {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		children := make([]HierarchyNode, 0, len(dirs))
		for _, dir := range dirs {
			node := *byDir[dir]
			node.AttachedManifest = attachedManifestFor(parentManifests, &node)
			children = append(children, node)
		}
		return children
	}

	root.Children = childModules(".", root.ManifestIndexes)
	subprojectDirs := make([]string, 0, len(subprojects))
	for dir := range subprojects {
		subprojectDirs = append(subprojectDirs, dir)
	}
	sort.Strings(subprojectDirs)
	for _, dir := range subprojectDirs {
		node := *subprojects[dir]
		node.Children = childModules(dir, node.ManifestIndexes)
		root.Children = append(root.Children, node)
	}
	return root
}

// ManifestRootName returns the package name of a manifest's root dependency —
// the project/module's own name (web, core-lib) — or "" when the manifest has
// no single unambiguous root. The root is the one dependency no other
// dependency in the manifest depends on.
func ManifestRootName(manifest ScanManifest) string {
	referenced := map[string]struct{}{}
	for _, dep := range manifest.Dependencies {
		for _, id := range dep.DependsOn {
			referenced[id] = struct{}{}
		}
	}
	rootName := ""
	roots := 0
	for _, dep := range manifest.Dependencies {
		if _, ok := referenced[dep.ID]; ok {
			continue
		}
		roots++
		rootName = dep.Name
	}
	if roots != 1 || strings.TrimSpace(rootName) == "" {
		return ""
	}
	return rootName
}

// normalizeHierarchyDir canonicalizes a subproject or manifest path to a
// clean slash form with "." for the root.
func normalizeHierarchyDir(value string) string {
	value = strings.Trim(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")), "/")
	if value == "" || value == "." {
		return "."
	}
	return path.Clean(value)
}
