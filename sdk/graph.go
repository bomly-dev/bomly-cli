package sdk

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNilNode          = errors.New("dependency node is nil")
	ErrEmptyNodeID      = errors.New("dependency node id is empty")
	ErrNodeAlreadyExist = errors.New("dependency node already exists")
	ErrNodeNotFound     = errors.New("dependency node not found")
	ErrSelfDependency   = errors.New("self dependency is not allowed")
	ErrCycleDetected    = errors.New("dependency creates a cycle")
)

// Path describes one dependency path through the graph.
type Path struct {
	Nodes   []*Dependency
	Cyclic  bool
	CycleTo string
}

// Diff summarizes the dependency changes between two graphs.
type Diff struct {
	Added   []*Dependency
	Removed []*Dependency
	Updated []VersionChange
}

// VersionChange captures a dependency identity that changed versions.
type VersionChange struct {
	Before *Dependency
	After  *Dependency
}

// Graph stores dependency nodes as a directed graph.
type Graph struct {
	indexByID map[string]int
	nodes     []*Dependency
	alive     []bool
	outgoing  []map[int]struct{}
	incoming  []map[int]struct{}
	free      []int
	size      int
}

// New creates an empty dependency graph.
func New() *Graph {
	return NewWithCapacity(0)
}

// NewWithCapacity creates an empty dependency graph sized for the expected node count.
func NewWithCapacity(nodeCount int) *Graph {
	return &Graph{
		indexByID: make(map[string]int, nodeCount),
		nodes:     make([]*Dependency, 0, nodeCount),
		alive:     make([]bool, 0, nodeCount),
		outgoing:  make([]map[int]struct{}, 0, nodeCount),
		incoming:  make([]map[int]struct{}, 0, nodeCount),
	}
}

// AddNode inserts a dependency node.
func (g *Graph) AddNode(node *Dependency) error {
	if node == nil {
		return ErrNilNode
	}
	if node.ID == "" {
		return ErrEmptyNodeID
	}
	if _, exists := g.indexByID[node.ID]; exists {
		return fmt.Errorf("%w: %s", ErrNodeAlreadyExist, node.ID)
	}

	idx := g.nextSlot()
	g.nodes[idx] = node
	g.alive[idx] = true
	g.outgoing[idx] = make(map[int]struct{})
	g.incoming[idx] = make(map[int]struct{})
	g.indexByID[node.ID] = idx
	g.size++
	return nil
}

// Node returns a dependency node by ID.
func (g *Graph) Node(id string) (*Dependency, bool) {
	idx, ok := g.indexByID[id]
	if !ok {
		return nil, false
	}
	return g.nodes[idx], ok
}

// Nodes returns all dependency nodes sorted by ID.
func (g *Graph) Nodes() []*Dependency {
	indices := g.sortedIndices()
	out := make([]*Dependency, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.nodes[idx])
	}
	return out
}

// AddEdge adds a dependency relationship fromID -> toID, meaning fromID
// depends on toID.
func (g *Graph) AddEdge(fromID, toID string) error {
	if fromID == toID {
		return ErrSelfDependency
	}
	fromIdx, err := g.requireIndex(fromID)
	if err != nil {
		return err
	}
	toIdx, err := g.requireIndex(toID)
	if err != nil {
		return err
	}
	if _, ok := g.outgoing[fromIdx][toIdx]; ok {
		return nil
	}
	g.outgoing[fromIdx][toIdx] = struct{}{}
	g.incoming[toIdx][fromIdx] = struct{}{}
	return nil
}

// RemoveEdge removes a dependency relationship and reports whether it existed.
func (g *Graph) RemoveEdge(fromID, toID string) bool {
	fromIdx, ok := g.indexByID[fromID]
	if !ok {
		return false
	}
	toIdx, ok := g.indexByID[toID]
	if !ok {
		return false
	}
	if _, ok = g.outgoing[fromIdx][toIdx]; !ok {
		return false
	}
	delete(g.outgoing[fromIdx], toIdx)
	delete(g.incoming[toIdx], fromIdx)
	return true
}

// RemoveNode removes a node and all incident relationships.
func (g *Graph) RemoveNode(id string) bool {
	idx, ok := g.indexByID[id]
	if !ok {
		return false
	}
	for depIdx := range g.outgoing[idx] {
		delete(g.incoming[depIdx], idx)
	}
	for parentIdx := range g.incoming[idx] {
		delete(g.outgoing[parentIdx], idx)
	}
	delete(g.indexByID, id)
	g.nodes[idx] = nil
	g.alive[idx] = false
	g.outgoing[idx] = nil
	g.incoming[idx] = nil
	g.free = append(g.free, idx)
	g.size--
	return true
}

// DirectDependencies returns direct dependencies for a node, sorted by ID.
func (g *Graph) DirectDependencies(id string) ([]*Dependency, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.outgoing[idx]), nil
}

// Dependents returns direct dependents for a node, sorted by ID.
func (g *Graph) Dependents(id string) ([]*Dependency, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.incoming[idx]), nil
}

// Roots returns nodes with no incoming relationships.
func (g *Graph) Roots() []*Dependency {
	out := make([]*Dependency, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.incoming[idx]) == 0 {
			out = append(out, g.nodes[idx])
		}
	}
	return out
}

// Leaves returns nodes with no outgoing relationships.
func (g *Graph) Leaves() []*Dependency {
	out := make([]*Dependency, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.outgoing[idx]) == 0 {
			out = append(out, g.nodes[idx])
		}
	}
	return out
}

// CollectPathsTo returns deterministic root-to-target dependency paths.
func (g *Graph) CollectPathsTo(targetID string) ([]Path, error) {
	targetIdx, err := g.requireIndex(targetID)
	if err != nil {
		return nil, err
	}

	relevant := g.reverseReachable(targetIdx)
	starts := g.relevantRoots(relevant)
	if len(starts) == 0 {
		starts = g.sortedRelevantIndices(relevant)
	}

	paths := make([]Path, 0)
	for _, startIdx := range starts {
		g.collectPathsTo(startIdx, targetIdx, relevant, nil, map[int]struct{}{}, &paths)
	}

	sort.Slice(paths, func(i, j int) bool {
		return pathNodesKey(paths[i].Nodes) < pathNodesKey(paths[j].Nodes)
	})
	return paths, nil
}

// TopologicalSort returns a topological ordering for the acyclic portion of the
// graph. If cycles remain, the returned slice contains the ordered prefix and
// ErrCycleDetected.
func (g *Graph) TopologicalSort() ([]*Dependency, error) {
	inDeg := make([]int, len(g.nodes))
	ready := &idIndexHeap{g: g, items: make([]int, 0, g.size)}
	for idx, node := range g.nodes {
		if node == nil || !g.alive[idx] {
			continue
		}
		inDeg[idx] = len(g.incoming[idx])
		if inDeg[idx] == 0 {
			heap.Push(ready, idx)
		}
	}

	ordered := make([]*Dependency, 0, g.size)
	for ready.Len() > 0 {
		idx := heap.Pop(ready).(int)
		ordered = append(ordered, g.nodes[idx])
		for childIdx := range g.outgoing[idx] {
			inDeg[childIdx]--
			if inDeg[childIdx] == 0 {
				heap.Push(ready, childIdx)
			}
		}
	}

	if len(ordered) != g.size {
		return ordered, ErrCycleDetected
	}
	return ordered, nil
}

// Size returns the number of nodes in the graph.
func (g *Graph) Size() int {
	return g.size
}

// WalkNodes iterates all live nodes. Returning false from fn stops iteration.
func (g *Graph) WalkNodes(fn func(*Dependency) bool) {
	if fn == nil {
		return
	}
	for idx, node := range g.nodes {
		if node == nil || !g.alive[idx] {
			continue
		}
		if !fn(node) {
			return
		}
	}
}

// WalkEdges iterates all dependency relationships (from -> to). Returning false
// stops iteration.
func (g *Graph) WalkEdges(fn func(from, to *Dependency) bool) {
	if fn == nil {
		return
	}
	for fromIdx, relationships := range g.outgoing {
		if !g.alive[fromIdx] || relationships == nil {
			continue
		}
		for toIdx := range relationships {
			if !g.alive[toIdx] {
				continue
			}
			if !fn(g.nodes[fromIdx], g.nodes[toIdx]) {
				return
			}
		}
	}
}

// PrettyString returns a stable, human-readable adjacency list.
func (g *Graph) PrettyString() string {
	if g.size == 0 {
		return "(empty graph)"
	}

	nodes := g.Nodes()
	var b strings.Builder
	for i, node := range nodes {
		deps, _ := g.DirectDependencies(node.ID)
		b.WriteString(node.ID)
		b.WriteString(" -> [")
		for j, dep := range deps {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(dep.ID)
		}
		b.WriteString("]")
		if i < len(nodes)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// PrettyTree returns an ASCII tree view of dependencies from graph roots.
func (g *Graph) PrettyTree() string {
	if g.size == 0 {
		return "(empty graph)"
	}

	roots := g.Roots()
	if len(roots) == 0 {
		roots = g.Nodes()
	}

	expanded := make(map[int]struct{}, g.size)
	var b strings.Builder
	for _, root := range roots {
		rootIdx := g.indexByID[root.ID]
		b.WriteString(nodeDisplayLabel(root))
		b.WriteByte('\n')
		expanded[rootIdx] = struct{}{}
		onPath := map[int]struct{}{rootIdx: {}}
		g.writeTree(&b, rootIdx, "", expanded, onPath)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Compare returns the added, removed, and updated dependencies between base and
// head. Synthetic consolidated subproject nodes are ignored.
func Compare(base, head *Graph) Diff {
	baseExact, headExact := indexDiffableNodes(base), indexDiffableNodes(head)
	baseRemainder := make(map[string]*Dependency)
	headRemainder := make(map[string]*Dependency)

	for id, node := range baseExact {
		if _, ok := headExact[id]; ok {
			continue
		}
		baseRemainder[id] = node
	}
	for id, node := range headExact {
		if _, ok := baseExact[id]; ok {
			continue
		}
		headRemainder[id] = node
	}

	baseByIdentity := groupNodesByIdentity(baseRemainder)
	headByIdentity := groupNodesByIdentity(headRemainder)
	identities := make(map[string]struct{}, len(baseByIdentity)+len(headByIdentity))
	for key := range baseByIdentity {
		identities[key] = struct{}{}
	}
	for key := range headByIdentity {
		identities[key] = struct{}{}
	}

	diff := Diff{
		Added:   make([]*Dependency, 0),
		Removed: make([]*Dependency, 0),
		Updated: make([]VersionChange, 0),
	}
	for key := range identities {
		baseNodes := baseByIdentity[key]
		headNodes := headByIdentity[key]
		sortNodesForDiff(baseNodes)
		sortNodesForDiff(headNodes)

		pairs := len(baseNodes)
		if len(headNodes) < pairs {
			pairs = len(headNodes)
		}
		for i := 0; i < pairs; i++ {
			diff.Updated = append(diff.Updated, VersionChange{Before: baseNodes[i], After: headNodes[i]})
		}
		if pairs < len(baseNodes) {
			diff.Removed = append(diff.Removed, baseNodes[pairs:]...)
		}
		if pairs < len(headNodes) {
			diff.Added = append(diff.Added, headNodes[pairs:]...)
		}
	}

	sortNodesForDiff(diff.Added)
	sortNodesForDiff(diff.Removed)
	sort.Slice(diff.Updated, func(i, j int) bool {
		left := diff.Updated[i]
		right := diff.Updated[j]
		if left.Before.IdentityKey() != right.Before.IdentityKey() {
			return left.Before.IdentityKey() < right.Before.IdentityKey()
		}
		if left.Before.Version != right.Before.Version {
			return left.Before.Version < right.Before.Version
		}
		if left.After.Version != right.After.Version {
			return left.After.Version < right.After.Version
		}
		return left.Before.ID < right.Before.ID
	})
	return diff
}

func indexDiffableNodes(g *Graph) map[string]*Dependency {
	indexed := make(map[string]*Dependency)
	if g == nil {
		return indexed
	}
	g.WalkNodes(func(node *Dependency) bool {
		if node == nil || !NodeIsDiffable(node) {
			return true
		}
		indexed[node.ID] = node
		return true
	})
	return indexed
}

// NodeIsDiffable reports whether node should participate in dependency diffs.
func NodeIsDiffable(node *Dependency) bool {
	if node == nil || strings.HasPrefix(node.ID, "subproject:") || strings.HasPrefix(node.ID, "manifest:") {
		return false
	}
	switch node.Type {
	case PackageTypeManifest, PackageTypeApplication:
		return false
	}
	name := strings.ToLower(strings.TrimSpace(node.Name))
	switch name {
	case "root", "package-lock.json", "yarn.lock", "pubspec.lock", "poetry.lock", "pipfile.lock", "mix.lock", "conan.lock", "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock":
		return false
	}
	if strings.HasSuffix(name, ".sbom.json") || strings.HasSuffix(name, ".spdx.json") || strings.HasSuffix(name, ".cdx.json") {
		return false
	}
	return true
}

// NodeIsEnrichable reports whether node should be queried against external
// enrichment sources (advisory databases, package registries, scorecards).
// Manifest-typed structural nodes and first-party artifacts (workspace
// members, reactor modules, the project's own package — marked FirstParty by
// the detector that synthesized them) are not published to public sources, so
// querying them wastes lookups and risks coincidental name matches; they
// remain in the packages inventory and in generated SBOMs, just without
// external enrichment. Ownership is the FirstParty marker, never the package
// type: an application-typed component imported from an SBOM is an artifact
// kind, not proof it belongs to the scanned project, and stays enrichable.
// External plugin matchers should apply the same predicate to the nodes they
// iterate.
func NodeIsEnrichable(node *Dependency) bool {
	if node == nil || node.FirstParty {
		return false
	}
	return node.Type != PackageTypeManifest
}

func groupNodesByIdentity(nodes map[string]*Dependency) map[string][]*Dependency {
	grouped := make(map[string][]*Dependency)
	for _, node := range nodes {
		grouped[node.IdentityKey()] = append(grouped[node.IdentityKey()], node)
	}
	return grouped
}

func sortNodesForDiff(nodes []*Dependency) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Version != nodes[j].Version {
			return nodes[i].Version < nodes[j].Version
		}
		return nodes[i].ID < nodes[j].ID
	})
}

func (g *Graph) lookupSorted(ids map[int]struct{}) []*Dependency {
	indices := make([]int, 0, len(ids))
	for idx := range ids {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].ID < g.nodes[indices[j]].ID
	})

	out := make([]*Dependency, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.nodes[idx])
	}
	return out
}

func (g *Graph) writeTree(b *strings.Builder, nodeIdx int, prefix string, expanded map[int]struct{}, onPath map[int]struct{}) {
	children := g.sortedAdjacent(g.outgoing[nodeIdx])
	for i, childIdx := range children {
		isLast := i == len(children)-1
		b.WriteString(prefix)
		if isLast {
			b.WriteString("`-- ")
		} else {
			b.WriteString("|-- ")
		}
		b.WriteString(nodeDisplayLabel(g.nodes[childIdx]))

		if _, seen := onPath[childIdx]; seen {
			b.WriteString(" (cycle)\n")
			continue
		}
		if _, seen := expanded[childIdx]; seen {
			b.WriteString(" (shared)\n")
			continue
		}

		b.WriteByte('\n')
		expanded[childIdx] = struct{}{}
		onPath[childIdx] = struct{}{}
		nextPrefix := prefix
		if isLast {
			nextPrefix += "    "
		} else {
			nextPrefix += "|   "
		}
		g.writeTree(b, childIdx, nextPrefix, expanded, onPath)
		delete(onPath, childIdx)
	}
}

func nodeDisplayLabel(node *Dependency) string {
	if node == nil {
		return ""
	}
	label := node.StableID()
	scope := node.PrimaryScope()
	if scope == ScopeUnknown {
		return label
	}
	return label + " [" + string(scope) + "]"
}

func (g *Graph) collectPathsTo(currentIdx, targetIdx int, relevant map[int]struct{}, stack []int, active map[int]struct{}, paths *[]Path) {
	if _, ok := relevant[currentIdx]; !ok {
		return
	}
	if _, seen := active[currentIdx]; seen {
		return
	}

	stack = append(stack, currentIdx)
	active[currentIdx] = struct{}{}
	defer delete(active, currentIdx)

	if currentIdx == targetIdx {
		*paths = append(*paths, g.buildPath(stack, false, ""))
	}

	for _, childIdx := range g.sortedAdjacent(g.outgoing[currentIdx]) {
		if _, ok := relevant[childIdx]; !ok {
			continue
		}
		if _, seen := active[childIdx]; seen {
			if childIdx == targetIdx {
				cycleStack := append(append([]int(nil), stack...), childIdx)
				*paths = append(*paths, g.buildPath(cycleStack, true, g.nodes[childIdx].ID))
			}
			continue
		}
		g.collectPathsTo(childIdx, targetIdx, relevant, stack, active, paths)
	}
}

func (g *Graph) buildPath(indices []int, cyclic bool, cycleTo string) Path {
	nodes := make([]*Dependency, 0, len(indices))
	for _, idx := range indices {
		nodes = append(nodes, g.nodes[idx])
	}
	return Path{
		Nodes:   nodes,
		Cyclic:  cyclic,
		CycleTo: cycleTo,
	}
}

func (g *Graph) reverseReachable(startIdx int) map[int]struct{} {
	reachable := map[int]struct{}{startIdx: {}}
	stack := []int{startIdx}
	for len(stack) > 0 {
		idx := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for parentIdx := range g.incoming[idx] {
			if _, seen := reachable[parentIdx]; seen {
				continue
			}
			reachable[parentIdx] = struct{}{}
			stack = append(stack, parentIdx)
		}
	}
	return reachable
}

func (g *Graph) relevantRoots(relevant map[int]struct{}) []int {
	roots := make([]int, 0, len(relevant))
	for _, idx := range g.sortedRelevantIndices(relevant) {
		hasRelevantParent := false
		for parentIdx := range g.incoming[idx] {
			if _, ok := relevant[parentIdx]; ok {
				hasRelevantParent = true
				break
			}
		}
		if !hasRelevantParent {
			roots = append(roots, idx)
		}
	}
	return roots
}

func (g *Graph) sortedRelevantIndices(relevant map[int]struct{}) []int {
	indices := make([]int, 0, len(relevant))
	for idx := range relevant {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].ID < g.nodes[indices[j]].ID
	})
	return indices
}

func pathNodesKey(nodes []*Dependency) string {
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	return strings.Join(ids, "/")
}

func (g *Graph) sortedAdjacent(adj map[int]struct{}) []int {
	indices := make([]int, 0, len(adj))
	for idx := range adj {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].ID < g.nodes[indices[j]].ID
	})
	return indices
}

func (g *Graph) sortedIndices() []int {
	indices := make([]int, 0, g.size)
	for _, idx := range g.indexByID {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].ID < g.nodes[indices[j]].ID
	})
	return indices
}

func (g *Graph) requireIndex(id string) (int, error) {
	idx, ok := g.indexByID[id]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrNodeNotFound, id)
	}
	return idx, nil
}

func (g *Graph) nextSlot() int {
	if n := len(g.free); n > 0 {
		idx := g.free[n-1]
		g.free = g.free[:n-1]
		return idx
	}

	g.nodes = append(g.nodes, nil)
	g.alive = append(g.alive, false)
	g.outgoing = append(g.outgoing, nil)
	g.incoming = append(g.incoming, nil)
	return len(g.nodes) - 1
}

type idIndexHeap struct {
	g     *Graph
	items []int
}

func (h *idIndexHeap) Len() int {
	return len(h.items)
}

func (h *idIndexHeap) Less(i, j int) bool {
	return h.g.nodes[h.items[i]].ID < h.g.nodes[h.items[j]].ID
}

func (h *idIndexHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
}

func (h *idIndexHeap) Push(x any) {
	h.items = append(h.items, x.(int))
}

func (h *idIndexHeap) Pop() any {
	old := h.items
	n := len(old)
	x := old[n-1]
	h.items = old[:n-1]
	return x
}
