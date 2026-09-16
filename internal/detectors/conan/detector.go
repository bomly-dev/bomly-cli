package conan

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Detector resolves Conan dependency graphs from committed Conan files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

var evidencePatterns = []string{"conan.lock", "conanfile.txt", "conanfile.py", "conaninfo.txt"}

type conanRef struct {
	Name    string
	Version string
	Context string
	Direct  bool
}

type graphInfo struct {
	Graph struct {
		Nodes map[string]graphNode `json:"nodes"`
	} `json:"graph"`
}

type graphNode struct {
	Ref           string   `json:"ref"`
	Context       string   `json:"context"`
	Requires      []string `json:"requires"`
	BuildRequires []string `json:"build_requires"`
}

type conanLock struct {
	Requires []string `json:"requires"`
	Graph    struct {
		Nodes map[string]graphNode `json:"nodes"`
	} `json:"graph"`
	GraphLock struct {
		Nodes map[string]graphNode `json:"nodes"`
	} `json:"graph_lock"`
}

var conanRefPattern = regexp.MustCompile(`([A-Za-z0-9_.+-]+)/([A-Za-z0-9_.+:-]+)`)

// PackageManagerSupport returns Conan package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerConan, evidencePatterns...)}
}

// Ready reports whether committed Conan files can be parsed.
func (d Detector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether Conan files are present.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range []string{"conan.lock", "conanfile.txt", "conanfile.py", "conaninfo.txt"} {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// Descriptor describes the Conan detector.
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		Name:                detectors.NameConan,
		Technique:           plugin.LockfileTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemCPP},
		SupportedManagers:   []model.PackageManager{model.PackageManagerConan},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a Conan dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	g, err := depGraphFromConanFiles(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachConanPositions(g, workingDir)
	return detectors.Attributed(plugin.DetectionResult{Graphs: model.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns))}), nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func depGraphFromConanFiles(workingDir string) (*model.Graph, error) {
	for _, name := range []string{"conan.lock"} {
		raw, err := readOptional(filepath.Join(workingDir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if len(raw) == 0 {
			continue
		}
		if g, err := depGraphFromJSON(raw); err == nil {
			return g, nil
		}
	}
	return depGraphFromManifestFiles(workingDir)
}

func depGraphFromJSON(raw []byte) (*model.Graph, error) {
	var info graphInfo
	if err := json.Unmarshal(raw, &info); err == nil && len(info.Graph.Nodes) > 0 {
		return depGraphFromNodes(info.Graph.Nodes)
	}
	var lock conanLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Conan JSON: %w", err)
	}
	switch {
	case len(lock.Graph.Nodes) > 0:
		return depGraphFromNodes(lock.Graph.Nodes)
	case len(lock.GraphLock.Nodes) > 0:
		return depGraphFromNodes(lock.GraphLock.Nodes)
	case len(lock.Requires) > 0:
		refs := make([]conanRef, 0, len(lock.Requires))
		for _, value := range lock.Requires {
			if ref, ok := parseConanRef(value); ok {
				ref.Direct = true
				refs = append(refs, ref)
			}
		}
		return depGraphFromRefs(refs)
	default:
		return nil, fmt.Errorf("conan JSON does not contain graph nodes or requirements")
	}
}

func depGraphFromNodes(nodes map[string]graphNode) (*model.Graph, error) {
	g := model.New()
	root, err := rootNode()
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	nodePackages := make(map[string]*model.DependencyNode, len(nodes))
	for id, item := range nodes {
		ref, ok := parseConanRef(item.Ref)
		if !ok {
			// Node "0" is the project root (empty ref); skip adding it as a package.
			continue
		}
		ref.Context = item.Context
		node, err := packageNode(ref)
		if err != nil {
			return nil, err
		}
		nodePackages[id] = node
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	// Wire up root → direct deps from node "0" (the project root node).
	if rootItem, ok := nodes["0"]; ok {
		for _, depID := range rootItem.Requires {
			child, ok := nodePackages[depID]
			if !ok {
				continue
			}
			child.AddScope(model.ScopeRuntime)
			if err := g.AddEdge(root.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add Conan root dep %q: %w", child.NodeID(), err)
			}
		}
		for _, depID := range rootItem.BuildRequires {
			child, ok := nodePackages[depID]
			if !ok {
				continue
			}
			child.AddScope(model.ScopeDevelopment)
			if err := g.AddEdge(root.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add Conan root build dep %q: %w", child.NodeID(), err)
			}
		}
	}
	for _, id := range sortedNodeIDs(nodePackages) {
		node := nodePackages[id]
		item := nodes[id]
		for _, depID := range append(item.Requires, item.BuildRequires...) {
			child, ok := nodePackages[depID]
			if !ok {
				continue
			}
			if containsString(item.BuildRequires, depID) {
				child.AddScope(model.ScopeDevelopment)
			} else {
				child.AddScope(model.ScopeRuntime)
			}
			if err := g.AddEdge(node.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add Conan dependency %q -> %q: %w", node.NodeID(), child.NodeID(), err)
			}
		}
	}
	return g, nil
}

func depGraphFromManifestFiles(workingDir string) (*model.Graph, error) {
	var refs []conanRef
	for _, name := range []string{"conanfile.txt", "conanfile.py", "conaninfo.txt"} {
		raw, err := readOptional(filepath.Join(workingDir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if len(raw) == 0 {
			continue
		}
		for _, ref := range parseManifestRefs(string(raw)) {
			ref.Direct = true
			refs = append(refs, ref)
		}
	}
	return depGraphFromRefs(refs)
}

func depGraphFromRefs(refs []conanRef) (*model.Graph, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("conan files do not contain any dependencies")
	}
	g := model.New()
	root, err := rootNode()
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		node, err := packageNode(ref)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[node.NodeID()]; ok {
			continue
		}
		seen[node.NodeID()] = struct{}{}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add Conan root dependency %q: %w", node.NodeID(), err)
		}
	}
	return g, nil
}

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return system.ReadRepositoryFile(path)
}

func parseManifestRefs(raw string) []conanRef {
	matches := conanRefPattern.FindAllStringSubmatch(raw, -1)
	refs := make([]conanRef, 0, len(matches))
	for _, match := range matches {
		ref := conanRef{Name: match[1], Version: match[2]}
		if strings.Contains(raw[:strings.Index(raw, match[0])], "[tool_requires]") || strings.Contains(raw[:strings.Index(raw, match[0])], "tool_requires") {
			ref.Context = "build"
		}
		refs = append(refs, ref)
	}
	return refs
}

func parseConanRef(value string) (conanRef, bool) {
	match := conanRefPattern.FindStringSubmatch(value)
	if len(match) == 0 {
		return conanRef{}, false
	}
	return conanRef{Name: match[1], Version: match[2]}, true
}

func rootNode() (*model.ModuleNode, error) {
	return model.NewModuleNode("conanfile.txt", model.Coordinates{Ecosystem: model.EcosystemCPP,
		Name:           "root",
		PackageManager: model.PackageManagerConan,
		Type:           model.PackageTypeApplication,
		Language:       "cpp"})

}

func packageNode(ref conanRef) (*model.DependencyNode, error) {
	pkg, err := model.NewDependencyNode(model.Coordinates{Ecosystem: model.EcosystemCPP,
		Name:           strings.TrimSpace(ref.Name),
		Version:        strings.TrimSpace(ref.Version),
		PackageManager: model.PackageManagerConan,
		Type:           model.PackageTypePackage,
		Language:       "cpp",
		PURL:           model.BuildPackageURLFor(model.EcosystemCPP, model.PackageManagerConan, "", ref.Name, ref.Version)})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}

	if strings.EqualFold(strings.TrimSpace(ref.Context), "build") {
		pkg.AddScope(model.ScopeDevelopment)
	}
	return pkg, nil
}

func sortedNodeIDs(nodes map[string]*model.DependencyNode) []string {
	values := make([]string, 0, len(nodes))
	for id := range nodes {
		values = append(values, id)
	}
	sort.Strings(values)
	return values
}

func containsString(values []string, target string) bool {
	return slices.Contains(values, target)
}

func addNodeIfMissing(g *model.Graph, node *model.DependencyNode) error {
	_, err := detectorkit.EnsureNode(g, node)
	return err
}
