package conan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves Conan dependency graphs from committed Conan files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
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
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerConan, evidencePatterns...)}
}

// Ready reports whether committed Conan files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Conan files are present.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
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
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameConan,
		Enabled:             true,
		ComponentType:       model.NativeComponent,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemCPP},
		SupportedManagers:   []model.PackageManager{model.PackageManagerConan},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a Conan dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	g, err := depGraphFromConanFiles(workingDir)
	if err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{Graphs: model.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns))}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() model.Detector {
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
		return nil, fmt.Errorf("Conan JSON does not contain graph nodes or requirements")
	}
}

func depGraphFromNodes(nodes map[string]graphNode) (*model.Graph, error) {
	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	nodePackages := make(map[string]*model.Package, len(nodes))
	for id, item := range nodes {
		ref, ok := parseConanRef(item.Ref)
		if !ok {
			continue
		}
		ref.Context = item.Context
		node := packageNode(ref)
		nodePackages[id] = node
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	for _, id := range sortedNodeIDs(nodePackages) {
		node := nodePackages[id]
		item := nodes[id]
		parent := root
		if id != "0" {
			parent = node
		}
		for _, depID := range append(item.Requires, item.BuildRequires...) {
			child, ok := nodePackages[depID]
			if !ok {
				continue
			}
			if containsString(item.BuildRequires, depID) {
				model.MergePackageScope(child, model.ScopeDevelopment)
			}
			if err := g.AddDependency(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add Conan dependency %q -> %q: %w", parent.ID, child.ID, err)
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
		return nil, fmt.Errorf("Conan files do not contain any dependencies")
	}
	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		node := packageNode(ref)
		if _, ok := seen[node.ID]; ok {
			continue
		}
		seen[node.ID] = struct{}{}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddDependency(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add Conan root dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return os.ReadFile(path)
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

func rootNode() *model.Package {
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemCPP),
		Name:        "root",
		BuildSystem: model.PackageManagerConan.Name(),
		Type:        "application",
		Language:    "cpp",
	})
}

func packageNode(ref conanRef) *model.Package {
	pkg := model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemCPP),
		Name:        strings.TrimSpace(ref.Name),
		Version:     strings.TrimSpace(ref.Version),
		BuildSystem: model.PackageManagerConan.Name(),
		Type:        "package",
		Language:    "cpp",
		PURL:        model.BuildPackageURL("conan", "", ref.Name, ref.Version),
	})
	if strings.EqualFold(strings.TrimSpace(ref.Context), "build") {
		model.MergePackageScope(pkg, model.ScopeDevelopment)
	}
	return pkg
}

func sortedNodeIDs(nodes map[string]*model.Package) []string {
	values := make([]string, 0, len(nodes))
	for id := range nodes {
		values = append(values, id)
	}
	sort.Strings(values)
	return values
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func addNodeIfMissing(g *model.Graph, node *model.Package) error {
	if _, ok := g.Package(node.ID); ok {
		return nil
	}
	if err := g.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
