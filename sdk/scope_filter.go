package sdk

import "fmt"

// FilterGraphByScope returns a graph view containing roots plus dependencies
// whose normalized scope matches the requested filter.
func FilterGraphByScope(src *Graph, scope Scope) (*Graph, error) {
	if src == nil || scope == ScopeUnknown {
		return src, nil
	}

	allowed := make(map[string]struct{}, src.Size())
	for _, root := range src.Roots() {
		if root == nil {
			continue
		}
		allowed[root.ID] = struct{}{}
	}
	src.WalkNodes(func(dep *Dependency) bool {
		if dep != nil && dep.HasScope(scope) {
			allowed[dep.ID] = struct{}{}
		}
		return true
	})

	filtered := NewWithCapacity(len(allowed))
	for id := range allowed {
		dep, ok := src.Node(id)
		if !ok {
			continue
		}
		if err := filtered.AddNode(dep.Clone()); err != nil {
			return nil, err
		}
	}

	var mergeErr error
	src.WalkEdges(func(from, to *Dependency) bool {
		if from == nil || to == nil {
			return true
		}
		if _, ok := allowed[from.ID]; !ok {
			return true
		}
		if _, ok := allowed[to.ID]; !ok {
			return true
		}
		if err := filtered.AddEdge(from.ID, to.ID); err != nil {
			mergeErr = fmt.Errorf("add filtered edge %q -> %q: %w", from.ID, to.ID, err)
			return false
		}
		return true
	})
	if mergeErr != nil {
		return nil, mergeErr
	}

	return filtered, nil
}

// FilterDetectionResultByScope applies scope filtering to each graph entry in a
// detector result.
func FilterDetectionResultByScope(result DetectionResult, scope Scope) (DetectionResult, error) {
	if scope == ScopeUnknown || result.Graphs == nil {
		return result, nil
	}
	entries := make([]GraphEntry, 0, len(result.Graphs.Entries))
	for _, entry := range result.Graphs.Entries {
		if entry.Graph == nil {
			entries = append(entries, entry)
			continue
		}
		graphView, err := FilterGraphByScope(entry.Graph, scope)
		if err != nil {
			return DetectionResult{}, err
		}
		entry.Graph = graphView
		entry.Packages = filterEntryPackagesByGraph(entry.Packages, graphView)
		entries = append(entries, entry)
	}
	result.Graphs = &GraphContainer{Entries: entries}
	return result, nil
}

func filterEntryPackagesByGraph(packages []*Package, graph *Graph) []*Package {
	if len(packages) == 0 || graph == nil {
		return packages
	}
	allowed := make(map[string]struct{}, graph.Size())
	graph.WalkNodes(func(dep *Dependency) bool {
		if dep == nil {
			return true
		}
		if purl := CanonicalPackageURLFromDependency(dep); purl != "" {
			allowed[purl] = struct{}{}
		}
		return true
	})
	if len(allowed) == 0 {
		return nil
	}
	filtered := make([]*Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		if _, ok := allowed[pkg.PURL]; ok {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}
