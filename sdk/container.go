package sdk

import "errors"

// ManifestKind identifies the manifest family represented by one graph entry.
type ManifestKind = string

// ManifestMetadata describes the manifest or evidence file associated with one graph.
type ManifestMetadata struct {
	Path string       `json:"path,omitempty"`
	Kind ManifestKind `json:"kind,omitempty"`
}

// GraphEntry describes one manifest-scoped dependency graph.
type GraphEntry struct {
	Graph    *Graph           `json:"graph,omitempty"`
	Manifest ManifestMetadata `json:"manifest"`
}

// GraphContainer groups one or more manifest-scoped dependency graphs.
type GraphContainer struct {
	Entries []GraphEntry `json:"entries,omitempty"`
}

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *Graph, manifest ManifestMetadata) *GraphContainer {
	if g == nil {
		return &GraphContainer{}
	}
	return &GraphContainer{
		Entries: []GraphEntry{{
			Graph:    g,
			Manifest: manifest,
		}},
	}
}

// Len returns the number of graph entries.
func (c *GraphContainer) Len() int {
	if c == nil {
		return 0
	}
	return len(c.Entries)
}

// ConsolidatedGraph materializes a single graph view for the container.
func (c *GraphContainer) ConsolidatedGraph() (*Graph, error) {
	if c == nil || len(c.Entries) == 0 {
		return nil, nil
	}
	if len(c.Entries) == 1 {
		return c.Entries[0].Graph, nil
	}

	merged := New()
	for _, entry := range c.Entries {
		if entry.Graph == nil {
			continue
		}
		if err := MergeGraph(merged, entry.Graph); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// MergeGraph adds all packages and relationships from src into dst.
func MergeGraph(dst, src *Graph) error {
	if dst == nil || src == nil {
		return nil
	}
	var mergeErr error
	src.WalkPackages(func(pkg *Package) bool {
		if err := addPackageIfMissing(dst, pkg); err != nil {
			mergeErr = err
			return false
		}
		return true
	})
	if mergeErr != nil {
		return mergeErr
	}
	src.WalkRelationships(func(from, to *Package) bool {
		if err := dst.AddDependency(from.ID, to.ID); err != nil {
			mergeErr = err
			return false
		}
		return true
	})
	return mergeErr
}

func addPackageIfMissing(g *Graph, pkg *Package) error {
	if pkg == nil {
		return nil
	}
	clone := pkg.Clone()
	err := g.AddPackage(clone)
	if err != nil && !errors.Is(err, ErrPackageAlreadyExist) {
		return err
	}
	return nil
}

// ConsolidateGraphContainerEntry ensures one entry is present.
func ConsolidateGraphContainerEntry(container *GraphContainer) (*Graph, error) {
	if container == nil {
		return nil, nil
	}
	return container.ConsolidatedGraph()
}
