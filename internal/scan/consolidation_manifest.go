package scan

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func normalizeNativeManifestPath(subproject model.Subproject, manifestPath string) string {
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

func manifestDedupKey(subproject model.Subproject, manifest model.ManifestMetadata) string {
	p := manifestDedupPath(subproject, manifest.Path)
	return p
}

func manifestDedupPath(subproject model.Subproject, manifestPath string) string {
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

func consolidatedEntryRootID(g *model.Graph, manifest model.ManifestMetadata, idx int) string {
	if g != nil {
		roots := g.Roots()
		if len(roots) > 0 && roots[0] != nil && strings.TrimSpace(roots[0].ID) != "" {
			return roots[0].ID
		}
		packages := g.Packages()
		if len(packages) > 0 && packages[0] != nil && strings.TrimSpace(packages[0].ID) != "" {
			return packages[0].ID
		}
	}
	if strings.TrimSpace(manifest.Path) != "" {
		return strings.TrimSpace(manifest.Path)
	}
	return fmt.Sprintf("entry-%d", idx+1)
}

func ensureEntryRoot(g *model.Graph, manifest model.ManifestMetadata, idx int) error {
	if g == nil || g.Size() == 0 {
		return nil
	}
	if hasSingleRoot(g) {
		return nil
	}

	rootID := virtualManifestRootID(g, manifest, idx)
	manifestLabel := strings.TrimSpace(manifest.Path)
	if manifestLabel == "" {
		manifestLabel = fmt.Sprintf("entry-%d", idx+1)
	}
	manifestLabel = strings.ReplaceAll(manifestLabel, "\\", "/")

	kind := strings.TrimSpace(manifest.Kind)
	if kind == "" {
		kind = "manifest"
	}

	virtualRoot := model.NewPackageWithID(rootID, model.Package{
		Name:        manifestLabel,
		Type:        "manifest",
		BuildSystem: kind,
	})
	if err := addPackageIfMissing(g, virtualRoot); err != nil {
		return err
	}

	targets := g.Roots()
	if len(targets) == 0 {
		targets = g.Packages()
	}
	for _, target := range targets {
		if target == nil || target.ID == rootID {
			continue
		}
		if err := g.AddDependency(rootID, target.ID); err != nil {
			if errors.Is(err, model.ErrSelfDependency) {
				continue
			}
			return fmt.Errorf("attach virtual root %q -> %q: %w", rootID, target.ID, err)
		}
	}

	return nil
}

func hasSingleRoot(g *model.Graph) bool {
	if g == nil {
		return false
	}
	roots := g.Roots()
	return len(roots) == 1 && roots[0] != nil && strings.TrimSpace(roots[0].ID) != ""
}

func virtualManifestRootID(g *model.Graph, manifest model.ManifestMetadata, idx int) string {
	base := strings.TrimSpace(manifest.Path)
	if base == "" {
		base = fmt.Sprintf("entry-%d", idx+1)
	}
	base = strings.ReplaceAll(base, "\\", "/")

	if _, exists := g.Package(base); !exists {
		return base
	}

	candidate := "manifest:" + base
	if _, exists := g.Package(candidate); !exists {
		return candidate
	}

	for i := 2; ; i++ {
		next := fmt.Sprintf("%s#%d", candidate, i)
		if _, exists := g.Package(next); !exists {
			return next
		}
	}
}
