package nuget

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves NuGet dependency graphs from committed lockfiles.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"packages.lock.json", "packages.config", "*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj", "project.assets.json"}

type lockFile struct {
	Dependencies map[string]map[string]lockPackage `json:"dependencies"`
}

type lockPackage struct {
	Type         string            `json:"type"`
	Requested    string            `json:"requested"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

type packagesConfig struct {
	Packages []packagesConfigPackage `xml:"package"`
}

type packagesConfigPackage struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// PackageManagerSupport returns NuGet package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNuGet, evidencePatterns...)}
}

// Ready reports whether the detector can parse committed NuGet files.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether a NuGet lockfile or legacy packages.config is present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range []string{"packages.lock.json", "packages.config"} {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// Descriptor describes the NuGet detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameNuGet,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemDotNet},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerNuGet},
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a NuGet dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockPath := filepath.Join(workingDir, "packages.lock.json")
	if ok, err := system.FileExists(lockPath); err != nil {
		return sdk.DetectionResult{}, err
	} else if ok {
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			return sdk.DetectionResult{}, fmt.Errorf("read NuGet lockfile: %w", err)
		}
		g, err := depGraphFromLock(raw)
		if err != nil {
			return sdk.DetectionResult{}, err
		}
		return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, []string{"packages.lock.json"}))}, nil
	}

	configPath := filepath.Join(workingDir, "packages.config")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read NuGet packages.config: %w", err)
	}
	g, err := depGraphFromPackagesConfig(raw)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, []string{"packages.config"}))}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func depGraphFromLock(raw []byte) (*sdk.Graph, error) {
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse NuGet lockfile: %w", err)
	}
	g := sdk.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	packages := make(map[string]lockPackage)
	for _, targetPackages := range lock.Dependencies {
		for name, pkg := range targetPackages {
			if strings.TrimSpace(name) == "" {
				continue
			}
			existing := packages[name]
			if existing.Resolved == "" {
				packages[name] = pkg
				continue
			}
			if existing.Resolved != pkg.Resolved {
				packages[name+"@"+pkg.Resolved] = pkg
			}
		}
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("NuGet lockfile does not contain any packages")
	}

	for name, pkg := range packages {
		node := packageNode(baseName(name), pkg.Resolved, pkg)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	for name, pkg := range packages {
		parent := packageNode(baseName(name), pkg.Resolved, pkg)
		for depName := range pkg.Dependencies {
			depPkg, ok := findNuGetPackage(packages, depName)
			if !ok {
				continue
			}
			child := packageNode(baseName(depName), depPkg.Resolved, depPkg)
			if err := addNodeIfMissing(g, child); err != nil {
				return nil, err
			}
			if err := g.AddDependency(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add NuGet dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	roots := directNuGetRoots(packages)
	for _, name := range roots {
		pkg, _ := findNuGetPackage(packages, name)
		node := packageNode(baseName(name), pkg.Resolved, pkg)
		if existing, ok := g.Package(node.ID); ok {
			sdk.MergePackageScope(existing, sdk.ScopeRuntime)
		}
		if err := g.AddDependency(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add NuGet root dependency %q: %w", node.ID, err)
		}
	}
	if err := propagateScope(g, packages, roots, sdk.ScopeRuntime); err != nil {
		return nil, err
	}
	return g, nil
}

func depGraphFromPackagesConfig(raw []byte) (*sdk.Graph, error) {
	var config packagesConfig
	if err := xml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse NuGet packages.config: %w", err)
	}
	if len(config.Packages) == 0 {
		return nil, fmt.Errorf("NuGet packages.config does not contain any packages")
	}
	g := sdk.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, pkg := range config.Packages {
		if strings.TrimSpace(pkg.ID) == "" {
			continue
		}
		node := packageNode(pkg.ID, pkg.Version, lockPackage{})
		sdk.MergePackageScope(node, sdk.ScopeRuntime)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddDependency(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add NuGet packages.config dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func rootNode() *sdk.Package {
	return sdk.NewPackage(sdk.Package{
		Ecosystem:   string(sdk.EcosystemDotNet),
		Name:        "root",
		BuildSystem: sdk.PackageManagerNuGet.Name(),
		Type:        "application",
		Language:    "dotnet",
	})
}

func packageNode(name, version string, pkg lockPackage) *sdk.Package {
	node := sdk.NewPackage(sdk.Package{
		Ecosystem:   string(sdk.EcosystemDotNet),
		Name:        name,
		Version:     version,
		BuildSystem: sdk.PackageManagerNuGet.Name(),
		Type:        "package",
		Language:    "dotnet",
		PURL:        sdk.BuildPackageURL("nuget", "", name, version),
	})
	if pkg.ContentHash != "" {
		node.Digests = append(node.Digests, sdk.Digest{Algorithm: "nuget-content-hash", Value: pkg.ContentHash})
	}
	return node
}

func directNuGetRoots(packages map[string]lockPackage) []string {
	values := make([]string, 0)
	for name, pkg := range packages {
		if strings.EqualFold(strings.TrimSpace(pkg.Type), "direct") {
			values = append(values, baseName(name))
		}
	}
	sort.Strings(values)
	return values
}

func findNuGetPackage(packages map[string]lockPackage, name string) (lockPackage, bool) {
	for candidate, pkg := range packages {
		if strings.EqualFold(baseName(candidate), name) {
			return pkg, true
		}
	}
	return lockPackage{}, false
}

func baseName(name string) string {
	if i := strings.LastIndex(name, "@"); i > 0 {
		return name[:i]
	}
	return name
}

func propagateScope(g *sdk.Graph, packages map[string]lockPackage, roots []string, scope sdk.Scope) error {
	visited := make(map[string]struct{}, len(packages))
	var walk func(string) error
	walk = func(name string) error {
		if _, ok := visited[strings.ToLower(name)]; ok {
			return nil
		}
		visited[strings.ToLower(name)] = struct{}{}
		pkg, ok := findNuGetPackage(packages, name)
		if !ok {
			return nil
		}
		node := packageNode(name, pkg.Resolved, pkg)
		if existing, ok := g.Package(node.ID); ok {
			sdk.MergePackageScope(existing, scope)
		}
		for depName := range pkg.Dependencies {
			if err := walk(depName); err != nil {
				return err
			}
		}
		return nil
	}
	for _, root := range roots {
		if err := walk(root); err != nil {
			return err
		}
	}
	return nil
}

func addNodeIfMissing(g *sdk.Graph, node *sdk.Package) error {
	if _, ok := g.Package(node.ID); ok {
		return nil
	}
	if err := g.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
