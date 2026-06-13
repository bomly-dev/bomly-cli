package sdk

import "errors"

// ManifestKind identifies the manifest family represented by one graph entry.
type ManifestKind string

const (
	// ManifestKindPackageLockJSON identifies npm package-lock.json manifests.
	ManifestKindPackageLockJSON ManifestKind = "package-lock.json"
	// ManifestKindNPMLockfile identifies generic npm lockfile manifests.
	ManifestKindNPMLockfile ManifestKind = "npm-lockfile"
	// ManifestKindPackageJSON identifies npm package.json manifests.
	ManifestKindPackageJSON ManifestKind = "package.json"
	// ManifestKindGoMod identifies Go module manifests.
	ManifestKindGoMod ManifestKind = "go.mod"
	// ManifestKindGoModule identifies normalized Go module manifests.
	ManifestKindGoModule ManifestKind = "go-module"
	// ManifestKindPomXML identifies Maven POM manifests.
	ManifestKindPomXML ManifestKind = "pom.xml"
	// ManifestKindRequirementsTXT identifies Python requirements manifests.
	ManifestKindRequirementsTXT ManifestKind = "requirements.txt"
	// ManifestKindSPDX identifies SPDX SBOM manifests.
	ManifestKindSPDX ManifestKind = "spdx"
	// ManifestKindSBOM identifies generic SBOM manifests.
	ManifestKindSBOM ManifestKind = "sbom"
	// ManifestKindGitHubSPDX identifies GitHub-produced SPDX SBOM manifests.
	ManifestKindGitHubSPDX ManifestKind = "github.spdx"
	// ManifestKindBomlySPDX identifies Bomly-produced SPDX SBOM manifests.
	ManifestKindBomlySPDX ManifestKind = "bomly.spdx"
	// ManifestKindGitHubActions identifies GitHub Actions manifests.
	ManifestKindGitHubActions ManifestKind = "github-actions"
	// ManifestKindGitHubActionsWorkflow identifies GitHub Actions workflow files.
	ManifestKindGitHubActionsWorkflow ManifestKind = "github-actions-workflow"
	// ManifestKindGitHubActionsAction identifies GitHub Actions action metadata files.
	ManifestKindGitHubActionsAction ManifestKind = "github-actions-action"
)

// ManifestMetadata describes the manifest or evidence file associated with one graph.
type ManifestMetadata struct {
	Path string       `json:"path,omitempty"`
	Kind ManifestKind `json:"kind,omitempty"`
}

// GraphEntry describes one manifest-scoped dependency graph. Detection-time
// package facts discovered alongside the graph (licenses, digests, copyright
// pulled from lockfiles) are carried in Packages for folding into the global
// package registry during consolidation.
type GraphEntry struct {
	Graph    *Graph           `json:"graph,omitempty"`
	Manifest ManifestMetadata `json:"manifest"`
	Packages []*Package       `json:"packages,omitempty"`
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

// MergeGraph adds all nodes and relationships from src into dst.
func MergeGraph(dst, src *Graph) error {
	if dst == nil || src == nil {
		return nil
	}
	var mergeErr error
	src.WalkNodes(func(node *Dependency) bool {
		if err := addNodeIfMissing(dst, node); err != nil {
			mergeErr = err
			return false
		}
		return true
	})
	if mergeErr != nil {
		return mergeErr
	}
	src.WalkEdges(func(from, to *Dependency) bool {
		if err := dst.AddEdge(from.ID, to.ID); err != nil {
			mergeErr = err
			return false
		}
		return true
	})
	return mergeErr
}

func addNodeIfMissing(g *Graph, node *Dependency) error {
	if node == nil {
		return nil
	}
	clone := node.Clone()
	err := g.AddNode(clone)
	if err != nil && !errors.Is(err, ErrNodeAlreadyExist) {
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
