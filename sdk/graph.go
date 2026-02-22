package sdk

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNilPackage          = errors.New("package is nil")
	ErrEmptyPackageID      = errors.New("package id is empty")
	ErrPackageAlreadyExist = errors.New("package already exists")
	ErrPackageNotFound     = errors.New("package not found")
	ErrSelfDependency      = errors.New("self dependency is not allowed")
	ErrCycleDetected       = errors.New("dependency creates a cycle")
)

// Path describes one dependency path through the graph.
type Path struct {
	Packages []*Package
	Cyclic   bool
	CycleTo  string
}

// Diff summarizes the dependency changes between two graphs.
type Diff struct {
	Added   []*Package
	Removed []*Package
	Updated []VersionChange
}

// VersionChange captures a package identity that changed versions.
type VersionChange struct {
	Before *Package
	After  *Package
}

// Graph stores dependencies as a directed graph.
type Graph struct {
	indexByID map[string]int
	packages  []*Package
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

// NewWithCapacity creates an empty dependency graph sized for the expected number of packages.
func NewWithCapacity(packageCount int) *Graph {
	return &Graph{
		indexByID: make(map[string]int, packageCount),
		packages:  make([]*Package, 0, packageCount),
		alive:     make([]bool, 0, packageCount),
		outgoing:  make([]map[int]struct{}, 0, packageCount),
		incoming:  make([]map[int]struct{}, 0, packageCount),
	}
}

// AddPackage inserts a dependency package.
func (g *Graph) AddPackage(pkg *Package) error {
	if pkg == nil {
		return ErrNilPackage
	}
	if pkg.ID == "" {
		return ErrEmptyPackageID
	}
	if _, exists := g.indexByID[pkg.ID]; exists {
		return fmt.Errorf("%w: %s", ErrPackageAlreadyExist, pkg.ID)
	}

	idx := g.nextSlot()
	g.packages[idx] = pkg
	g.alive[idx] = true
	g.outgoing[idx] = make(map[int]struct{})
	g.incoming[idx] = make(map[int]struct{})
	g.indexByID[pkg.ID] = idx
	g.size++
	return nil
}

// Package returns a package by ID.
func (g *Graph) Package(id string) (*Package, bool) {
	idx, ok := g.indexByID[id]
	if !ok {
		return nil, false
	}
	return g.packages[idx], ok
}

// Packages returns all packages sorted by ID.
func (g *Graph) Packages() []*Package {
	indices := g.sortedIndices()
	out := make([]*Package, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.packages[idx])
	}
	return out
}

// AddDependency adds a dependency relationship fromID -> toID,
// meaning fromID depends on toID.
func (g *Graph) AddDependency(fromID, toID string) error {
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

// RemoveDependency removes a dependency relationship and reports whether it existed.
func (g *Graph) RemoveDependency(fromID, toID string) bool {
	fromIdx, ok := g.indexByID[fromID]
	if !ok {
		return false
	}
	toIdx, ok := g.indexByID[toID]
	if !ok {
		return false
	}
	_, ok = g.outgoing[fromIdx][toIdx]
	if !ok {
		return false
	}
	delete(g.outgoing[fromIdx], toIdx)
	delete(g.incoming[toIdx], fromIdx)
	return true
}

// RemovePackage removes a package and all incident relationships.
func (g *Graph) RemovePackage(id string) bool {
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
	g.packages[idx] = nil
	g.alive[idx] = false
	g.outgoing[idx] = nil
	g.incoming[idx] = nil
	g.free = append(g.free, idx)
	g.size--
	return true
}

// Dependencies returns direct dependencies for a package, sorted by ID.
func (g *Graph) Dependencies(id string) ([]*Package, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.outgoing[idx]), nil
}

// Dependents returns direct dependents for a package, sorted by ID.
func (g *Graph) Dependents(id string) ([]*Package, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.incoming[idx]), nil
}

// Roots returns packages with no incoming relationships (nothing depends on them).
func (g *Graph) Roots() []*Package {
	out := make([]*Package, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.incoming[idx]) == 0 {
			out = append(out, g.packages[idx])
		}
	}
	return out
}

// Leaves returns packages with no outgoing relationships (no dependencies).
func (g *Graph) Leaves() []*Package {
	out := make([]*Package, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.outgoing[idx]) == 0 {
			out = append(out, g.packages[idx])
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
		return pathPackagesKey(paths[i].Packages) < pathPackagesKey(paths[j].Packages)
	})
	return paths, nil
}

// TopologicalSort returns a topological ordering for the acyclic portion of the graph.
// If cycles remain, the returned slice contains the ordered prefix and ErrCycleDetected.
func (g *Graph) TopologicalSort() ([]*Package, error) {
	inDeg := make([]int, len(g.packages))
	ready := &idIndexHeap{g: g, items: make([]int, 0, g.size)}
	for idx, pkg := range g.packages {
		if pkg == nil || !g.alive[idx] {
			continue
		}
		inDeg[idx] = len(g.incoming[idx])
		if inDeg[idx] == 0 {
			heap.Push(ready, idx)
		}
	}

	ordered := make([]*Package, 0, g.size)
	for ready.Len() > 0 {
		idx := heap.Pop(ready).(int)
		ordered = append(ordered, g.packages[idx])

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

// Size returns number of packages in the graph.
func (g *Graph) Size() int {
	return g.size
}

// WalkPackages iterates all live packages. Returning false from fn stops iteration.
func (g *Graph) WalkPackages(fn func(*Package) bool) {
	if fn == nil {
		return
	}
	for idx, pkg := range g.packages {
		if pkg == nil || !g.alive[idx] {
			continue
		}
		if !fn(pkg) {
			return
		}
	}
}

// WalkRelationships iterates all dependency relationships (from -> to).
// Returning false stops iteration.
func (g *Graph) WalkRelationships(fn func(from, to *Package) bool) {
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
			if !fn(g.packages[fromIdx], g.packages[toIdx]) {
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

	packages := g.Packages()
	var b strings.Builder
	for i, pkg := range packages {
		deps, _ := g.Dependencies(pkg.ID)
		b.WriteString(pkg.ID)
		b.WriteString(" -> [")
		for j, dep := range deps {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(dep.ID)
		}
		b.WriteString("]")
		if i < len(packages)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// PrettyTree returns an ASCII tree view of dependencies from graph roots.
// Cyclic relationships are rendered once with a "(cycle)" marker.
func (g *Graph) PrettyTree() string {
	if g.size == 0 {
		return "(empty graph)"
	}

	roots := g.Roots()
	if len(roots) == 0 {
		roots = g.Packages()
	}

	expanded := make(map[int]struct{}, g.size)
	var b strings.Builder
	for _, root := range roots {
		rootIdx := g.indexByID[root.ID]
		b.WriteString(packageDisplayLabel(root))
		b.WriteByte('\n')
		expanded[rootIdx] = struct{}{}
		onPath := map[int]struct{}{rootIdx: {}}
		g.writeTree(&b, rootIdx, "", expanded, onPath)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Compare returns the added, removed, and updated dependencies between base and head.
// Synthetic consolidated subproject packages are ignored.
func Compare(base, head *Graph) Diff {
	baseExact, headExact := indexDiffablePackages(base), indexDiffablePackages(head)
	baseRemainder := make(map[string]*Package)
	headRemainder := make(map[string]*Package)

	for id, pkg := range baseExact {
		if _, ok := headExact[id]; ok {
			continue
		}
		baseRemainder[id] = pkg
	}
	for id, pkg := range headExact {
		if _, ok := baseExact[id]; ok {
			continue
		}
		headRemainder[id] = pkg
	}

	baseByIdentity := groupPackagesByIdentity(baseRemainder)
	headByIdentity := groupPackagesByIdentity(headRemainder)
	identities := make(map[string]struct{}, len(baseByIdentity)+len(headByIdentity))
	for key := range baseByIdentity {
		identities[key] = struct{}{}
	}
	for key := range headByIdentity {
		identities[key] = struct{}{}
	}

	diff := Diff{
		Added:   make([]*Package, 0),
		Removed: make([]*Package, 0),
		Updated: make([]VersionChange, 0),
	}
	for key := range identities {
		basePackages := baseByIdentity[key]
		headPackages := headByIdentity[key]
		sortPackagesForDiff(basePackages)
		sortPackagesForDiff(headPackages)

		pairs := len(basePackages)
		if len(headPackages) < pairs {
			pairs = len(headPackages)
		}
		for i := 0; i < pairs; i++ {
			diff.Updated = append(diff.Updated, VersionChange{Before: basePackages[i], After: headPackages[i]})
		}
		if pairs < len(basePackages) {
			diff.Removed = append(diff.Removed, basePackages[pairs:]...)
		}
		if pairs < len(headPackages) {
			diff.Added = append(diff.Added, headPackages[pairs:]...)
		}
	}

	sortPackagesForDiff(diff.Added)
	sortPackagesForDiff(diff.Removed)
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

func indexDiffablePackages(g *Graph) map[string]*Package {
	indexed := make(map[string]*Package)
	if g == nil {
		return indexed
	}
	g.WalkPackages(func(pkg *Package) bool {
		if pkg == nil || strings.HasPrefix(pkg.ID, "subproject:") || strings.HasPrefix(pkg.ID, "manifest:") {
			return true
		}
		indexed[pkg.ID] = pkg
		return true
	})
	return indexed
}

func groupPackagesByIdentity(packages map[string]*Package) map[string][]*Package {
	grouped := make(map[string][]*Package)
	for _, pkg := range packages {
		grouped[pkg.IdentityKey()] = append(grouped[pkg.IdentityKey()], pkg)
	}
	return grouped
}

func sortPackagesForDiff(packages []*Package) {
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
}

func (g *Graph) lookupSorted(ids map[int]struct{}) []*Package {
	indices := make([]int, 0, len(ids))
	for idx := range ids {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.packages[indices[i]].ID < g.packages[indices[j]].ID
	})

	out := make([]*Package, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.packages[idx])
	}
	return out
}

func (g *Graph) writeTree(b *strings.Builder, packageIdx int, prefix string, expanded map[int]struct{}, onPath map[int]struct{}) {
	children := g.sortedAdjacent(g.outgoing[packageIdx])
	for i, childIdx := range children {
		isLast := i == len(children)-1
		b.WriteString(prefix)
		if isLast {
			b.WriteString("`-- ")
		} else {
			b.WriteString("|-- ")
		}
		b.WriteString(packageDisplayLabel(g.packages[childIdx]))

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

func packageDisplayLabel(pkg *Package) string {
	if pkg == nil {
		return ""
	}
	label := pkg.StableID()
	if pkg.Scope == "" {
		return label
	}
	return label + " [" + pkg.Scope + "]"
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
				*paths = append(*paths, g.buildPath(cycleStack, true, g.packages[childIdx].ID))
			}
			continue
		}
		g.collectPathsTo(childIdx, targetIdx, relevant, stack, active, paths)
	}
}

func (g *Graph) buildPath(indices []int, cyclic bool, cycleTo string) Path {
	packages := make([]*Package, 0, len(indices))
	for _, idx := range indices {
		packages = append(packages, g.packages[idx])
	}
	return Path{
		Packages: packages,
		Cyclic:   cyclic,
		CycleTo:  cycleTo,
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
		return g.packages[indices[i]].ID < g.packages[indices[j]].ID
	})
	return indices
}

func pathPackagesKey(packages []*Package) string {
	ids := make([]string, 0, len(packages))
	for _, pkg := range packages {
		ids = append(ids, pkg.ID)
	}
	return strings.Join(ids, "/")
}

func (g *Graph) sortedAdjacent(adj map[int]struct{}) []int {
	indices := make([]int, 0, len(adj))
	for idx := range adj {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.packages[indices[i]].ID < g.packages[indices[j]].ID
	})
	return indices
}

func (g *Graph) sortedIndices() []int {
	indices := make([]int, 0, g.size)
	for _, idx := range g.indexByID {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.packages[indices[i]].ID < g.packages[indices[j]].ID
	})
	return indices
}

func (g *Graph) requireIndex(id string) (int, error) {
	idx, ok := g.indexByID[id]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrPackageNotFound, id)
	}
	return idx, nil
}

func (g *Graph) nextSlot() int {
	if n := len(g.free); n > 0 {
		idx := g.free[n-1]
		g.free = g.free[:n-1]
		return idx
	}

	g.packages = append(g.packages, nil)
	g.alive = append(g.alive, false)
	g.outgoing = append(g.outgoing, nil)
	g.incoming = append(g.incoming, nil)
	return len(g.packages) - 1
}

type idIndexHeap struct {
	g     *Graph
	items []int
}

func (h idIndexHeap) Len() int {
	return len(h.items)
}

func (h idIndexHeap) Less(i, j int) bool {
	return h.g.packages[h.items[i]].ID < h.g.packages[h.items[j]].ID
}

func (h idIndexHeap) Swap(i, j int) {
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
