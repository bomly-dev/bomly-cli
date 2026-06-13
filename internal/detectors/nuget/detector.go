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

// Detector resolves NuGet dependency graphs from committed NuGet manifests.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"packages.lock.json", "*.deps.json", "packages.config", "*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj", "project.assets.json"}
var projectFilePatterns = []string{"*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj"}

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

type depsFile struct {
	Targets   map[string]map[string]depsTarget `json:"targets"`
	Libraries map[string]depsLibrary           `json:"libraries"`
}

type depsTarget struct {
	Dependencies map[string]string `json:"dependencies"`
}

type depsLibrary struct {
	Type   string `json:"type"`
	SHA512 string `json:"sha512"`
}

type packagesConfig struct {
	Packages []packagesConfigPackage `xml:"package"`
}

type packagesConfigPackage struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type projectFile struct {
	ItemGroups []projectItemGroup `xml:"ItemGroup"`
}

type projectItemGroup struct {
	PackageReferences []projectPackageReference `xml:"PackageReference"`
}

type projectPackageReference struct {
	Include        string `xml:"Include,attr"`
	Update         string `xml:"Update,attr"`
	Version        string `xml:"Version,attr"`
	VersionElement string `xml:"Version"`
}

// PackageManagerSupport returns NuGet package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNuGet, evidencePatterns...)}
}

// Ready reports whether the detector can parse committed NuGet files.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether a NuGet lockfile, legacy packages.config, or project file is present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range []string{"packages.lock.json", "packages.config"} {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	depsFiles, err := nugetDepsFiles(workingDir)
	if err != nil {
		return false, err
	}
	if len(depsFiles) > 0 {
		return true, nil
	}
	projectFiles, err := nugetProjectFiles(workingDir)
	if err != nil {
		return false, err
	}
	if len(projectFiles) > 0 {
		return true, nil
	}
	return false, nil
}

// Descriptor describes the NuGet detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameNuGet,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemDotNet},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerNuGet},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
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
		AttachNugetPositions(g, workingDir)
		return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, []string{"packages.lock.json"}))}, nil
	}

	depsFiles, err := nugetDepsFiles(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	if len(depsFiles) > 0 {
		g, err := depGraphFromDepsFiles(depsFiles)
		if err != nil {
			return sdk.DetectionResult{}, err
		}
		AttachNugetPositions(g, workingDir)
		return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, []string{"*.deps.json"}))}, nil
	}

	configPath := filepath.Join(workingDir, "packages.config")
	raw, err := os.ReadFile(configPath)
	if err == nil {
		g, err := depGraphFromPackagesConfig(raw)
		if err != nil {
			return sdk.DetectionResult{}, err
		}
		AttachNugetPositions(g, workingDir)
		return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, []string{"packages.config"}))}, nil
	}
	if !os.IsNotExist(err) {
		return sdk.DetectionResult{}, fmt.Errorf("read NuGet packages.config: %w", err)
	}

	projectFiles, err := nugetProjectFiles(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	g, err := depGraphFromProjectFiles(projectFiles)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachNugetPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, projectFilePatterns))}, nil
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
	if err := g.AddNode(root); err != nil {
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
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add NuGet dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	roots := directNuGetRoots(packages)
	for _, name := range roots {
		pkg, _ := findNuGetPackage(packages, name)
		node := packageNode(baseName(name), pkg.Resolved, pkg)
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeRuntime)
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
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
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, pkg := range config.Packages {
		if strings.TrimSpace(pkg.ID) == "" {
			continue
		}
		node := packageNode(pkg.ID, pkg.Version, lockPackage{})
		node.AddScope(sdk.ScopeRuntime)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add NuGet packages.config dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func depGraphFromDepsFiles(paths []string) (*sdk.Graph, error) {
	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	packageEntries := make(map[string]lockPackage)
	rootDeps := make(map[string]string)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read NuGet deps file %q: %w", path, err)
		}
		var deps depsFile
		if err := json.Unmarshal(raw, &deps); err != nil {
			return nil, fmt.Errorf("parse NuGet deps file %q: %w", path, err)
		}
		for _, targetPackages := range deps.Targets {
			for key, target := range targetPackages {
				name, version, ok := splitDepsPackageKey(key)
				if !ok {
					continue
				}
				library := deps.Libraries[key]
				if !strings.EqualFold(strings.TrimSpace(library.Type), "package") {
					for depName, depVersion := range target.Dependencies {
						rootDeps[depName] = depVersion
					}
					continue
				}
				pkg := lockPackage{
					Type:         "transitive",
					Resolved:     version,
					ContentHash:  strings.TrimPrefix(library.SHA512, "sha512-"),
					Dependencies: target.Dependencies,
				}
				packageEntries[name] = pkg
			}
		}
	}
	if len(packageEntries) == 0 {
		return nil, fmt.Errorf("NuGet deps files do not contain package entries")
	}
	selected := reachableNuGetPackages(packageEntries, rootDeps)
	for name, pkg := range selected {
		if err := addNodeIfMissing(g, packageNode(name, pkg.Resolved, pkg)); err != nil {
			return nil, err
		}
	}
	for name, pkg := range selected {
		parent := packageNode(name, pkg.Resolved, pkg)
		for depName := range pkg.Dependencies {
			depPkg, ok := findNuGetPackage(selected, depName)
			if !ok {
				continue
			}
			child := packageNode(depName, depPkg.Resolved, depPkg)
			if err := addNodeIfMissing(g, child); err != nil {
				return nil, err
			}
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add NuGet deps dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}
	roots := make([]string, 0, len(rootDeps))
	for depName := range rootDeps {
		pkg, ok := findNuGetPackage(selected, depName)
		if !ok {
			continue
		}
		node := packageNode(depName, pkg.Resolved, pkg)
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeRuntime)
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add NuGet deps root dependency %q: %w", node.ID, err)
		}
		roots = append(roots, depName)
	}
	sort.Strings(roots)
	if err := propagateScope(g, selected, roots, sdk.ScopeRuntime); err != nil {
		return nil, err
	}
	return g, nil
}

func depGraphFromProjectFiles(paths []string) (*sdk.Graph, error) {
	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	seen := make(map[string]struct{})
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read NuGet project file %q: %w", path, err)
		}
		var project projectFile
		if err := xml.Unmarshal(raw, &project); err != nil {
			return nil, fmt.Errorf("parse NuGet project file %q: %w", path, err)
		}
		for _, ref := range project.packageReferences() {
			name := strings.TrimSpace(firstNonEmpty(ref.Include, ref.Update))
			version := strings.TrimSpace(firstNonEmpty(ref.Version, ref.VersionElement))
			if name == "" || version == "" {
				continue
			}
			node := packageNode(name, version, lockPackage{})
			node.AddScope(sdk.ScopeRuntime)
			if _, ok := seen[node.ID]; ok {
				continue
			}
			seen[node.ID] = struct{}{}
			if err := addNodeIfMissing(g, node); err != nil {
				return nil, err
			}
			if err := g.AddEdge(root.ID, node.ID); err != nil {
				return nil, fmt.Errorf("add NuGet project dependency %q: %w", node.ID, err)
			}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("NuGet project files do not contain any PackageReference entries")
	}
	return g, nil
}

func (p projectFile) packageReferences() []projectPackageReference {
	values := make([]projectPackageReference, 0)
	for _, group := range p.ItemGroups {
		values = append(values, group.PackageReferences...)
	}
	return values
}

func nugetProjectFiles(dir string) ([]string, error) {
	return nugetFilesByPattern(dir, isNuGetProjectFile, "match NuGet project files")
}

func nugetDepsFiles(dir string) ([]string, error) {
	return nugetFilesByPattern(dir, func(path string) bool {
		return strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".deps.json")
	}, "match NuGet deps files")
}

func nugetFilesByPattern(dir string, match func(string) bool, context string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry == nil || entry.IsDir() {
			if entry != nil && strings.EqualFold(entry.Name(), ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if match(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	sort.Strings(files)
	return files, nil
}

func isNuGetProjectFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csproj", ".fsproj", ".vbproj", ".vcxproj":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemDotNet,
		Name:           "root",
		PackageManager: sdk.PackageManagerNuGet,
		Type:           sdk.PackageTypeApplication,
		Language:       "dotnet"},
	})

}

func packageNode(name, version string, pkg lockPackage) *sdk.Dependency {
	node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemDotNet,
		Name:           name,
		Version:        version,
		PackageManager: sdk.PackageManagerNuGet,
		Type:           sdk.PackageTypePackage,
		Language:       "dotnet",
		PURL:           sdk.BuildPackageURL("nuget", "", name, version)},
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

func reachableNuGetPackages(packages map[string]lockPackage, roots map[string]string) map[string]lockPackage {
	if len(roots) == 0 {
		return packages
	}
	selected := make(map[string]lockPackage, len(packages))
	var walk func(string)
	walk = func(name string) {
		for candidate, pkg := range packages {
			if !strings.EqualFold(baseName(candidate), name) {
				continue
			}
			if _, ok := selected[candidate]; ok {
				return
			}
			selected[candidate] = pkg
			for depName := range pkg.Dependencies {
				walk(depName)
			}
			return
		}
	}
	for name := range roots {
		walk(name)
	}
	if len(selected) == 0 {
		return packages
	}
	return selected
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

func splitDepsPackageKey(value string) (string, string, bool) {
	name, version, ok := strings.Cut(strings.TrimSpace(value), "/")
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	return name, version, ok && name != "" && version != ""
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
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(scope)
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

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := g.Node(node.ID); ok {
		return nil
	}
	if err := g.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
