package consolidation

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// NormalizeManifestPath renders a detector-reported manifest path the way the
// consolidated manifests carry it: relative to the subproject's execution target
// in slash form. Warnings that name a file go through this so an absolute path
// inside a temporary clone directory never reaches output.
func NormalizeManifestPath(subproject sdk.Subproject, manifestPath string) string {
	return normalizeNativeManifestPath(subproject, manifestPath)
}

func normalizeNativeManifestPath(subproject sdk.Subproject, manifestPath string) string {
	if manifestPath == "" {
		return manifestPath
	}
	if !manifestPathIsAbs(manifestPath) {
		return filepath.ToSlash(manifestPath)
	}

	root := strings.TrimSpace(subproject.ExecutionTarget.Location)
	if root != "" {
		if rel, ok := pathRelativeToRoot(root, manifestPath); ok {
			return rel
		}
	}
	if strings.TrimSpace(subproject.ExecutionTarget.Location) != "" {
		if rel, ok := pathRelativeToRoot(subproject.ExecutionTarget.Location, manifestPath); ok {
			return rel
		}
	}
	return filepath.ToSlash(filepath.Base(manifestPath))
}

func pathRelativeToRoot(root, target string) (string, bool) {
	if rel, ok := slashPathRelativeToRoot(root, target); ok {
		return rel, true
	}
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "" || rel == "." {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func slashPathRelativeToRoot(root, target string) (string, bool) {
	root = strings.TrimSpace(strings.ReplaceAll(root, "\\", "/"))
	target = strings.TrimSpace(strings.ReplaceAll(target, "\\", "/"))
	if root == "" || target == "" {
		return "", false
	}

	rootVolume, rootRemainder, rootHasVolume := splitPathVolume(root)
	targetVolume, targetRemainder, targetHasVolume := splitPathVolume(target)
	if rootHasVolume != targetHasVolume {
		return "", false
	}
	if rootHasVolume && !strings.EqualFold(rootVolume, targetVolume) {
		return "", false
	}

	rootClean := path.Clean(rootRemainder)
	targetClean := path.Clean(targetRemainder)
	rel, err := filepath.Rel(rootClean, targetClean)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func splitPathVolume(value string) (string, string, bool) {
	if len(value) >= 2 && value[1] == ':' {
		volume := strings.ToUpper(value[:2])
		remainder := value[2:]
		if remainder == "" {
			remainder = "/"
		}
		return volume, remainder, true
	}
	return "", value, false
}

// rebaseManifestPathToRoot prefixes the subproject's RelativePath onto a
// subproject-relative manifest path so consolidated manifest paths are
// repository-root-relative — the invariant manifestDedupKey relies on to keep
// same-named manifests in different subprojects distinct. A no-op for
// root-level subprojects (RelativePath "." or "") and for absolute paths. A
// subproject planned directly on a manifest file (e.g. an SBOM document) has
// the manifest itself as its RelativePath, which already is the rebased path.
func rebaseManifestPathToRoot(subproject sdk.Subproject, manifestPath string) string {
	rel := strings.Trim(strings.TrimSpace(strings.ReplaceAll(subproject.RelativePath, "\\", "/")), "/")
	if rel == "" || rel == "." || manifestPath == "" || manifestPathIsAbs(manifestPath) {
		return manifestPath
	}
	if rel == manifestPath || strings.HasSuffix(rel, "/"+manifestPath) {
		return rel
	}
	return rebaseLocationPath(manifestPath, rel)
}

// manifestDedupKey identifies a manifest across detector results. Core
// detector paths are repo-root-relative after rebaseManifestPathToRoot, so the
// normalized path alone distinguishes same-named manifests in different
// subprojects.
func manifestDedupKey(subproject sdk.Subproject, manifest sdk.ManifestMetadata) string {
	p := manifestDedupPath(subproject, manifest.Path)
	return p
}

func manifestDedupPath(subproject sdk.Subproject, manifestPath string) string {
	p := strings.TrimSpace(strings.ReplaceAll(manifestPath, "\\", "/"))
	if p == "" {
		return p
	}
	if !manifestPathIsAbs(p) {
		return p
	}
	if root := strings.TrimSpace(subproject.ExecutionTarget.Location); root != "" {
		if rel, ok := pathRelativeToRoot(root, p); ok {
			return rel
		}
	}
	if subproject.ExecutionTarget.Location != "" {
		if rel, ok := pathRelativeToRoot(subproject.ExecutionTarget.Location, p); ok {
			return rel
		}
	}
	return filepath.ToSlash(filepath.Base(p))
}

func manifestPathIsAbs(path string) bool {
	normalized := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	return filepath.IsAbs(path) || strings.HasPrefix(normalized, "/") || hasWindowsVolume(normalized)
}

func hasWindowsVolume(path string) bool {
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '/'
}

func consolidatedEntryRootID(g *sdk.Graph, manifest sdk.ManifestMetadata, idx int) string {
	if g != nil {
		roots := g.Roots()
		if len(roots) > 0 && roots[0] != nil && strings.TrimSpace(roots[0].NodeID()) != "" {
			return roots[0].NodeID()
		}
		nodes := g.DependencyNodes()
		if len(nodes) > 0 && nodes[0] != nil && strings.TrimSpace(nodes[0].NodeID()) != "" {
			return nodes[0].NodeID()
		}
	}
	if strings.TrimSpace(manifest.Path) != "" {
		return strings.TrimSpace(manifest.Path)
	}
	return fmt.Sprintf("entry-%d", idx+1)
}

func ensureEntryRoot(g *sdk.Graph, manifest sdk.ManifestMetadata, idx int) error {
	if g == nil || g.Size() == 0 {
		return nil
	}
	if hasSingleRoot(g) {
		return nil
	}

	roots := g.Roots()
	// Only dependency roots can be an application root or carry a
	// relationship; manifests and modules are structure.
	depRoots := make([]*sdk.DependencyNode, 0, len(roots))
	for _, root := range roots {
		if dep, ok := root.(*sdk.DependencyNode); ok {
			depRoots = append(depRoots, dep)
		}
	}
	if preferred := selectApplicationRoot(depRoots); preferred != nil {
		for _, target := range depRoots {
			if target == nil || target.NodeID() == preferred.NodeID() {
				continue
			}
			target.Relationship = sdk.DependencyRelationshipUnknown
			if err := g.AddEdge(preferred.NodeID(), target.NodeID()); err != nil {
				if errors.Is(err, sdk.ErrSelfDependency) {
					continue
				}
				return fmt.Errorf("attach application root %q -> %q: %w", preferred.NodeID(), target.NodeID(), err)
			}
		}
		return nil
	}

	rootID := virtualManifestRootID(g, manifest, idx)
	manifestLabel := strings.TrimSpace(manifest.Path)
	if manifestLabel == "" {
		manifestLabel = fmt.Sprintf("entry-%d", idx+1)
	}
	manifestLabel = strings.ReplaceAll(manifestLabel, "\\", "/")

	kind := strings.TrimSpace(string(manifest.Kind))
	if kind == "" {
		kind = "manifest"
	}

	// A synthesized root standing in for the manifest is a manifest node.
	// It was a dependency node typed PackageTypeManifest, which ADR-0041
	// replaced with the kind itself -- a structural node that is never
	// matched, never enriched, and never diffed as a package.
	virtualRoot, err := sdk.NewManifestNode(manifestLabel, manifest.Kind)
	if err != nil {
		return fmt.Errorf("build virtual manifest root %q: %w", manifestLabel, err)
	}
	if _, err := g.InsertNode(virtualRoot); err != nil {
		return fmt.Errorf("add virtual manifest root %q: %w", manifestLabel, err)
	}
	rootID = virtualRoot.NodeID()

	targets := g.Roots()
	if len(targets) == 0 {
		for _, dep := range g.DependencyNodes() {
			targets = append(targets, dep)
		}
	}
	for _, target := range targets {
		if target == nil || target.NodeID() == rootID {
			continue
		}
		if dep, ok := target.(*sdk.DependencyNode); ok && dep.Relationship == "" {
			dep.Relationship = sdk.DependencyRelationshipUnknown
		}
		if err := g.AddEdge(rootID, target.NodeID()); err != nil {
			if errors.Is(err, sdk.ErrSelfDependency) {
				continue
			}
			return fmt.Errorf("attach virtual root %q -> %q: %w", rootID, target.NodeID(), err)
		}
	}

	return nil
}

func selectApplicationRoot(roots []*sdk.DependencyNode) *sdk.DependencyNode {
	for _, root := range roots {
		if root == nil {
			continue
		}
		if root.Type == sdk.PackageTypeApplication {
			return root
		}
	}
	return nil
}

func packageManagerFromManifestKind(kind string) sdk.PackageManager {
	manager, err := sdk.ParsePackageManager(kind)
	if err != nil {
		return sdk.PackageManagerUnknown
	}
	return manager
}

func hasSingleRoot(g *sdk.Graph) bool {
	if g == nil {
		return false
	}
	roots := g.Roots()
	return len(roots) == 1 && roots[0] != nil && strings.TrimSpace(roots[0].NodeID()) != ""
}

func virtualManifestRootID(g *sdk.Graph, manifest sdk.ManifestMetadata, idx int) string {
	base := strings.TrimSpace(manifest.Path)
	if base == "" {
		base = fmt.Sprintf("entry-%d", idx+1)
	}
	base = strings.ReplaceAll(base, "\\", "/")

	if _, exists := g.Node(base); !exists {
		return base
	}

	candidate := "manifest:" + base
	if _, exists := g.Node(candidate); !exists {
		return candidate
	}

	for i := 2; ; i++ {
		next := fmt.Sprintf("%s#%d", candidate, i)
		if _, exists := g.Node(next); !exists {
			return next
		}
	}
}
