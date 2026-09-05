// Package graphview reads a dependency graph for presentation and publication.
//
// ADR-0041 made the graph a sealed union of manifest, module, and dependency
// nodes, and three questions come up wherever a graph is rendered or exported:
// what package URL does this node publish, which of a node's children can a
// document actually name, and which nodes count as top-level parents. The SDK
// answers what a node *is*; these answer what a consumer of a document may
// say about it, which is the CLI's own concern.
//
// They live here because the alternative is a copy per surface, and the copies
// disagree. Each of these shipped a defect from exactly that: the interactive
// view published a module's structural ID in a field labelled "PURL"; the scan
// JSON named a manifest in depends_on that no record defined, and the SBOM
// export did the same one commit after the first was fixed; and two separate
// directness classifiers read only graph roots, so a module that another
// module depends on had its direct dependencies reported as transitive.
//
// This is a leaf: it imports the SDK and nothing else from this repository, so
// the codec, the renderers, and the TUI can all reach it without any of them
// depending on each other.
//
// PurlFor is now a one-line delegation to sdk.NodePURL: the SDK took the
// projection in v0.9.2 (bomly-dev/bomly-sdk#43), which is where it belongs.
// ChildrenAmong and TopLevelParentIDs stay here -- what a document may name
// and what counts as a top-level parent are the CLI's decisions, not the
// model's.
package graphview

import sdk "github.com/bomly-dev/bomly-sdk"

// PurlFor returns the package URL a node publishes, or "" when it has none.
//
// It delegates to sdk.NodePURL, which is where this belongs (ADR-0040): the
// SDK owns what a node means, and the three kinds answer this differently.
// The CLI carried the projection while bomly-dev/bomly-sdk#43 was open, and
// v0.9.2 closed it -- the wrapper stays only so callers here read one name
// alongside ChildrenAmong and TopLevelParentIDs, which remain CLI policy.
func PurlFor(node sdk.GraphNode) string {
	return sdk.NodePURL(node)
}

// ChildrenAmong names a node's children among the IDs a document actually
// contains, stepping through the ones it does not.
//
// Manifest nodes are structural and are deliberately absent from scan JSON's
// dependency list and from an SBOM's components, but they sit in the middle
// of a real path: a workspace is module -> child manifest -> child module.
// Publishing the manifest's ID leaves a reference nothing resolves -- a
// dangling bom-ref in CycloneDX, an unresolvable depends_on in scan JSON --
// and dropping it outright severs the workspace so neither end of the hop can
// be reconstructed. Stepping through keeps the relationship the graph asserts,
// expressed only in IDs the document defines.
//
// Order follows the graph's own child order, which is sorted by ID. The
// visited set bounds a graph whose structural nodes form a cycle; a child that
// is present is recorded, never traversed.
func ChildrenAmong(g *sdk.Graph, nodeID string, present map[string]struct{}) []string {
	resolved := make([]string, 0)
	if g == nil {
		return resolved
	}
	seen := make(map[string]struct{})
	visited := map[string]struct{}{nodeID: {}}

	var walk func(id string)
	walk = func(id string) {
		children, err := g.DirectDependencies(id)
		if err != nil {
			return
		}
		for _, child := range children {
			if sdk.IsNilNode(child) {
				continue
			}
			childID := child.NodeID()
			if _, ok := present[childID]; ok {
				if _, duplicate := seen[childID]; !duplicate {
					seen[childID] = struct{}{}
					resolved = append(resolved, childID)
				}
				continue
			}
			if _, been := visited[childID]; been {
				continue
			}
			visited[childID] = struct{}{}
			walk(childID)
		}
	}
	walk(nodeID)
	return resolved
}

// TopLevelParentIDs returns the nodes whose direct children count as
// "top-level" dependencies: graph roots, every module node, and every
// application-typed dependency node.
//
// Workspace members and reactor modules may have incoming edges -- one module
// depending on another -- so a roots-only view hides the depended-on module's
// own direct dependencies and reports them as transitive. Under ADR-0041 such
// a member is a module node, which is why reading application-typed
// dependency nodes alone stopped finding them; that spelling is kept for a
// root a detector has not promoted yet.
func TopLevelParentIDs(g *sdk.Graph) map[string]struct{} {
	parents := make(map[string]struct{})
	if g == nil {
		return parents
	}
	for _, root := range g.Roots() {
		if !sdk.IsNilNode(root) {
			parents[root.NodeID()] = struct{}{}
		}
	}
	for _, module := range g.ModuleNodes() {
		if module != nil {
			parents[module.NodeID()] = struct{}{}
		}
	}
	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && pkg.Type == sdk.PackageTypeApplication {
			parents[pkg.NodeID()] = struct{}{}
		}
	}
	return parents
}
