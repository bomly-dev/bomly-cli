package detectors

import (
	"path"
	"sort"
	"strconv"
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// ModuleDeclarations carries what one module root's manifest declared about
// its direct dependencies, so the attribution below can record a site's real
// scope instead of the node-level union.
//
// The union is only lossy when a package is reached from more than one module
// root: a workspace can declare one package as a development dependency in one
// member and pull the same package in at runtime through another, and the node
// carries both. Detectors that already read per-module declarations (the node
// family reads them out of each package.json) pass them here; the rest do not
// need to, because with one module root the node's scopes are that root's.
//
// Scopes is keyed the way the node detectors already key declared scopes: by
// the dependency's name, falling back to its qualified name.
type ModuleDeclarations struct {
	// ModuleRoot is the module directory the declarations belong to, in the
	// same slash form Attributed derives from a module node's declaring
	// manifest ("." for the detector's own working directory).
	ModuleRoot string
	// Scopes maps a direct dependency's name to the scope this module
	// declared it under.
	Scopes map[string]sdk.Scope
}

// Attributed records, on every location the graphs in result carry, which
// module root's resolution produced that site, what the site's scopes are, and
// whether the site was declared by its module root or reached through another
// dependency. It returns result so a detector can wrap the value it was
// already returning.
//
// Per ADR-0037 the usage unit is (module root, declaration site): scope,
// relationship, and reachability answer questions about a usage, and a
// conjunctive filter has to find its conjuncts on one usage rather than on
// three different ones summarized onto the same node. The node-level Scopes
// union and Relationship scalar are left exactly as they were — this fills the
// per-site fields beside them.
//
// One site can belong to more than one module root: workspace members share a
// lockfile, so the same line is a usage in each member that reaches the
// package. Each (root, site) pair therefore becomes its own location record,
// which is why the module root is stored rather than inferred from the path.
//
// A graph with no module node is left untouched: an empty ModuleRoot documents
// that the producer did not attribute the site, and inventing a root here
// would put a directory into the join key that nothing observed.
//
// One limit is the SDK's, not this function's, and is recorded here because
// this is where the records are made: sdk's hasDependencyLocation compares a
// location's paths and position and nothing else, so if two separate nodes
// each carrying one root's record are merged into one, the second record is
// dropped. Entries that share node pointers -- how every workspace detector
// here partitions -- keep both, which is why the workspace case survives; two
// detectors resolving one package from one path would not. Widening that
// comparison to the module root belongs in the SDK.
func Attributed(result sdk.DetectionResult, declarations ...ModuleDeclarations) sdk.DetectionResult {
	if result.Graphs == nil {
		return result
	}
	declared := make(map[string]map[string]sdk.Scope, len(declarations))
	for _, declaration := range declarations {
		root := normalizeModuleRoot(declaration.ModuleRoot)
		if root == "" || len(declaration.Scopes) == 0 {
			continue
		}
		declared[root] = declaration.Scopes
	}

	roots := attributionRoots(result.Graphs, declared)
	if len(roots) == 0 {
		return result
	}
	// How many roots reach a node decides whether its own scope union is a
	// statement about a single site. Counted over every root first, because a
	// root only sees the graph it was found in.
	reachCount := make(map[string]int, len(roots))
	for i := range roots {
		for id := range roots[i].reached {
			reachCount[id]++
		}
	}
	dirs := make([]string, 0, len(roots))
	for i := range roots {
		dirs = append(dirs, roots[i].dir)
	}
	for i := range roots {
		roots[i].attribute(reachCount, dirs)
	}
	return result
}

// attributionRoot is one module root together with everything its resolution
// reached, and how.
type attributionRoot struct {
	dir      string
	nodeID   string
	graph    *sdk.Graph
	declared map[string]sdk.Scope
	reached  map[string]reachedSite
}

// reachedSite is what one module root observed about one node.
type reachedSite struct {
	node         sdk.GraphNode
	relationship sdk.DependencyRelationship
	// scope is the scope propagated from this root's declarations. Unknown
	// when the root declared nothing about the path that reached the node.
	scope sdk.Scope
}

// attributionRoots finds every module root across the result's entries and
// walks each one. Entries share node pointers when a detector partitions a
// workspace graph into per-member entries, which is exactly why a node can
// come back with one location record per member.
func attributionRoots(container *sdk.GraphContainer, declared map[string]map[string]sdk.Scope) []attributionRoot {
	var roots []attributionRoot
	seen := map[string]struct{}{}
	for _, entry := range container.Entries {
		if entry.Graph == nil {
			continue
		}
		for _, module := range entryModuleRoots(entry.Graph) {
			dir := normalizeModuleRoot(path.Dir(module.DeclaringManifestPath))
			key := dir + "\x00" + module.NodeID()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			root := attributionRoot{
				dir:      dir,
				nodeID:   module.NodeID(),
				graph:    entry.Graph,
				declared: declared[dir],
			}
			root.walk()
			roots = append(roots, root)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].dir != roots[j].dir {
			return roots[i].dir < roots[j].dir
		}
		return roots[i].nodeID < roots[j].nodeID
	})
	return roots
}

// entryModuleRoots returns the module nodes a graph is rooted in. Structural
// nodes are walked through — a manifest node declares nothing and owns
// nothing, so the module beneath it is the root that resolved the graph — and
// the walk stops at the first module on each path, because a workspace member
// depended on by a sibling is a dependency of that sibling, not a second root
// for it.
func entryModuleRoots(g *sdk.Graph) []*sdk.ModuleNode {
	var modules []*sdk.ModuleNode
	seen := map[string]struct{}{}
	queue := g.Roots()
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if _, ok := seen[current.NodeID()]; ok {
			continue
		}
		seen[current.NodeID()] = struct{}{}
		if module, ok := current.(*sdk.ModuleNode); ok {
			modules = append(modules, module)
			continue
		}
		if current.Kind() != sdk.NodeKindManifest {
			continue
		}
		children, err := g.DirectDependencies(current.NodeID())
		if err != nil {
			continue
		}
		queue = append(queue, children...)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].NodeID() < modules[j].NodeID() })
	return modules
}

// walk records what this module root reaches: the relationship of every node
// to it, and the scope propagated from its own declarations.
//
// The relationship is derived from this root's edges rather than read off
// sdk.RelationshipForPath, which prefers a node's stored Relationship — the
// merged scalar that cannot tell one root's direct declaration from another
// root's transitive path, and so cannot answer the per-site question. A node
// the detector explicitly marked unknown keeps unknown: its parent was never
// recovered, and this walk knows no better.
func (r *attributionRoot) walk() {
	r.reached = map[string]reachedSite{}
	root, ok := r.graph.Node(r.nodeID)
	if !ok {
		return
	}
	r.reached[r.nodeID] = reachedSite{node: root}

	directNodes, err := r.graph.DirectDependencies(r.nodeID)
	if err != nil {
		return
	}
	type queued struct {
		node  sdk.GraphNode
		scope sdk.Scope
	}
	queue := make([]queued, 0, len(directNodes))
	for _, direct := range directNodes {
		if direct == nil || direct.NodeID() == r.nodeID {
			continue
		}
		scope := r.declaredScope(direct)
		r.record(direct, sdk.DependencyRelationshipDirect, scope)
		queue = append(queue, queued{node: direct, scope: scope})
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		children, err := r.graph.DirectDependencies(current.node.NodeID())
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.NodeID() == r.nodeID {
				continue
			}
			// Monotone over a three-value scope lattice, so re-queueing only
			// while the merged value grows always settles — a cyclic graph
			// otherwise walks forever.
			existing, known := r.reached[child.NodeID()]
			next := sdk.MergeScope(existing.scope, current.scope)
			if known && next == existing.scope {
				continue
			}
			relationship := sdk.DependencyRelationshipTransitive
			if known {
				relationship = existing.relationship
			}
			r.record(child, relationship, next)
			queue = append(queue, queued{node: child, scope: next})
		}
	}
}

// record stores what the walk learned about one node, keeping the relationship
// a detector stated over the one the walk derived.
func (r *attributionRoot) record(node sdk.GraphNode, relationship sdk.DependencyRelationship, scope sdk.Scope) {
	if dependency, ok := sdk.AsDependencyNode(node); ok && dependency.Relationship == sdk.DependencyRelationshipUnknown {
		relationship = sdk.DependencyRelationshipUnknown
	}
	r.reached[node.NodeID()] = reachedSite{node: node, relationship: relationship, scope: scope}
}

// declaredScope returns the scope this module's manifest gave a direct
// dependency, or unknown when the detector supplied no declarations.
func (r *attributionRoot) declaredScope(node sdk.GraphNode) sdk.Scope {
	dependency, ok := sdk.AsDependencyNode(node)
	if !ok || len(r.declared) == 0 {
		return sdk.ScopeUnknown
	}
	if scope, ok := r.declared[dependency.Name]; ok {
		return scope
	}
	return r.declared[dependency.QualifiedName()]
}

// attribute writes this root's observations onto the locations of the nodes it
// reached.
func (r *attributionRoot) attribute(reachCount map[string]int, dirs []string) {
	ids := make([]string, 0, len(r.reached))
	for id := range r.reached {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		site := r.reached[id]
		locations := mutableNodeLocations(site.node)
		if locations == nil {
			continue
		}
		*locations = attributeSites(*locations, siteAttribution{
			moduleRoot:   r.dir,
			relationship: site.relationship,
			scopes:       r.siteScopes(site, reachCount),
			owns: func(location sdk.PackageLocation) bool {
				// A site at the top of the scan is shared by every module
				// that reaches it; a site inside a module's own directory
				// belongs to that module alone.
				owner := owningModuleDir(location, dirs)
				return owner == r.dir || owner == "."
			},
		})
	}
}

// siteScopes decides what this root can honestly say about the scopes of the
// sites it reached.
//
// With declarations, the propagated scope is this root's own. Without them the
// node's union is this root's view only when no other root reaches the node;
// when several do, the union mixes roots and the site's scopes stay empty
// rather than claiming a scope no one observed at that site.
func (r *attributionRoot) siteScopes(site reachedSite, reachCount map[string]int) []sdk.Scope {
	if site.scope != sdk.ScopeUnknown {
		return sdk.ScopesOf(site.scope)
	}
	dependency, ok := sdk.AsDependencyNode(site.node)
	if !ok || reachCount[site.node.NodeID()] != 1 {
		return nil
	}
	return sdk.ScopesOf(dependency.Scopes...)
}

// attributeSites returns locations carrying a record for this module root at
// every site they hold.
//
// A site with no attribution yet is filled in; a site already attributed to
// another root gains a second record, because that is a second usage. Running
// twice for one root changes nothing, which matters because entries share node
// pointers and a node is walked once per entry it appears in.
func attributeSites(locations []sdk.PackageLocation, attribution siteAttribution) []sdk.PackageLocation {
	moduleRoot, relationship, scopes := attribution.moduleRoot, attribution.relationship, attribution.scopes
	out := append([]sdk.PackageLocation(nil), locations...)
	attributed := make(map[string]struct{}, len(out))
	templates := make(map[string]sdk.PackageLocation, len(out))
	order := make([]string, 0, len(out))
	for _, location := range out {
		key := siteKey(location)
		if _, known := templates[key]; !known && attribution.owns(location) {
			templates[key] = location
			order = append(order, key)
		}
		if location.ModuleRoot == moduleRoot {
			attributed[key] = struct{}{}
		}
	}
	stamp := func(location *sdk.PackageLocation) {
		location.ModuleRoot = moduleRoot
		location.Relationship = relationship
		location.Scopes = append([]sdk.Scope(nil), scopes...)
	}
	for i := range out {
		key := siteKey(out[i])
		if _, done := attributed[key]; done || out[i].ModuleRoot != "" || !attribution.owns(out[i]) {
			continue
		}
		attributed[key] = struct{}{}
		stamp(&out[i])
	}
	for _, key := range order {
		if _, done := attributed[key]; done {
			continue
		}
		attributed[key] = struct{}{}
		record := templates[key]
		if record.Position != nil {
			position := *record.Position
			record.Position = &position
		}
		stamp(&record)
		out = append(out, record)
	}
	return out
}

// siteAttribution is one module root's view of the sites it reached: what to
// record, and which sites are its own to record it on.
type siteAttribution struct {
	moduleRoot   string
	relationship sdk.DependencyRelationship
	scopes       []sdk.Scope
	owns         func(sdk.PackageLocation) bool
}

// owningModuleDir returns the module whose directory contains a site, or "."
// when the site sits at the top of the scan.
//
// A file inside a member's own directory is that member's declaration -- a
// Maven reactor sibling must not claim module-a/pom.xml just because it
// resolves the same artifact. A file at the top, on the other hand, is shared:
// npm workspace members are all resolved from one package-lock.json, and each
// member's usage of a line in it is a usage of its own.
func owningModuleDir(location sdk.PackageLocation, dirs []string) string {
	path := strings.TrimSpace(toSlash(location.RealPath))
	if path == "" {
		path = strings.TrimSpace(toSlash(location.AccessPath))
	}
	owner := "."
	for _, dir := range dirs {
		if dir == "." || dir == "" {
			continue
		}
		if path != dir && !strings.HasPrefix(path, dir+"/") {
			continue
		}
		if len(dir) > len(owner) || owner == "." {
			owner = dir
		}
	}
	return owner
}

func toSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// siteKey identifies a declaration site: the paths and the position, never the
// attribution, which is what distinguishes two records of one site.
func siteKey(location sdk.PackageLocation) string {
	key := location.RealPath + "\x00" + location.AccessPath
	if location.Position == nil {
		return key
	}
	position := *location.Position
	return strings.Join([]string{
		key,
		position.File,
		strconv.Itoa(position.Line),
		strconv.Itoa(position.Column),
		strconv.Itoa(position.EndLine),
	}, "\x00")
}

// mutableNodeLocations returns a pointer to the node's own location slice, so
// an attributed record lands on the node rather than on a copy.
func mutableNodeLocations(node sdk.GraphNode) *[]sdk.PackageLocation {
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		if typed == nil {
			return nil
		}
		return &typed.Locations
	case *sdk.ModuleNode:
		if typed == nil {
			return nil
		}
		return &typed.Locations
	default:
		return nil
	}
}

// normalizeModuleRoot puts a module directory in the slash form the join key
// uses: "." for the detector's own working directory, no trailing slash.
func normalizeModuleRoot(dir string) string {
	dir = strings.TrimSpace(strings.ReplaceAll(dir, "\\", "/"))
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		return "."
	}
	return dir
}
