package detectors

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
)

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *model.Graph, manifest ManifestMetadata) *GraphContainer {
	return model.SingleGraphContainer(g, manifest)
}

// ConsolidatedGraph returns a single graph view for the resolve result.
func (r ResolveGraphResult) ConsolidatedGraph() (*model.Graph, error) {
	return model.ConsolidateGraphContainerEntry(r.Graphs)
}

// InferManifestMetadata determines the manifest metadata for detectors that naturally resolve one graph.
func InferManifestMetadata(req ResolveGraphRequest) ManifestMetadata {
	path := inferManifestPath(req)
	kind := manifestKindFromPath(path)
	if kind == "" {
		kind = req.PackageManager.Name()
	}
	return ManifestMetadata{
		Path: path,
		Kind: kind,
	}
}

func inferManifestPath(req ResolveGraphRequest) string {
	basePath := req.Subproject.ExecutionTarget.Location
	if basePath == "" {
		basePath = req.ProjectPath
	}
	if basePath == "" {
		basePath = req.ExecutionTarget.Location
	}
	if basePath == "" {
		return ""
	}

	info, err := os.Stat(basePath)
	if err == nil && !info.IsDir() {
		return basePath
	}

	for _, pattern := range EvidencePatternsForPackageManager(req.PackageManager) {
		candidate, ok := resolveManifestCandidate(basePath, pattern)
		if ok {
			return candidate
		}
	}
	return basePath
}

func resolveManifestCandidate(basePath, pattern string) (string, bool) {
	pattern = filepath.FromSlash(pattern)
	if pattern == "" {
		return "", false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		candidate := filepath.Join(basePath, pattern)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
		return "", false
	}

	matches, err := filepath.Glob(filepath.Join(basePath, pattern))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	for _, match := range matches {
		if info, statErr := os.Stat(match); statErr == nil && !info.IsDir() {
			return match, true
		}
	}
	return "", false
}

func manifestKindFromPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
