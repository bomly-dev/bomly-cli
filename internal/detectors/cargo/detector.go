package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var cargoExecLookPath = system.LookPath
var cargoExecCommand = system.Command

// Detector resolves Rust dependency graphs through cargo metadata.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"Cargo.lock", "Cargo.toml"}

type metadataOutput struct {
	Packages         []metadataPackage `json:"packages"`
	Resolve          metadataResolve   `json:"resolve"`
	WorkspaceMembers []string          `json:"workspace_members"`
}

type metadataPackage struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	Source       string               `json:"source"`
	Dependencies []metadataDependency `json:"dependencies"`
	ManifestPath string               `json:"manifest_path"`
}

type metadataDependency struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Optional bool   `json:"optional"`
}

type metadataResolve struct {
	Nodes []metadataNode `json:"nodes"`
}

type metadataNode struct {
	ID           string            `json:"id"`
	Dependencies []string          `json:"dependencies"`
	Deps         []metadataNodeDep `json:"deps"`
}

type metadataNodeDep struct {
	Name     string            `json:"name"`
	Package  string            `json:"pkg"`
	DepKinds []metadataDepKind `json:"dep_kinds"`
}

type metadataDepKind struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

// PackageManagerSupport returns Cargo package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerCargo, evidencePatterns...)}
}

// Ready reports whether Cargo is available.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether Cargo manifests are present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	return system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Cargo.toml"))
}

// Descriptor describes the Cargo detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameCargo,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemRust},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerCargo},
		Tags:                 []string{"graph-resolution", "component-targeting", "module-graph", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Cargo dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if ok, err := system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Cargo.lock")); err != nil {
		return sdk.DetectionResult{}, err
	} else if ok {
		return d.resolveFromLock(req)
	}

	cargoPath, err := cargoExecLookPath("cargo")
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("resolve cargo executable: %w", err)
	}
	args := []string{"metadata", "--format-version", "1", "--locked"}
	cmd := cargoExecCommand(cargoPath, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	logger.Debug("running cargo detector", zap.String("working_dir", cmd.Dir), zap.String("executable", cargoPath), zap.Strings("args", args))
	raw, err := cmd.Output()
	if err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("cargo detector failure details", fields...)
		return sdk.DetectionResult{}, fmt.Errorf("run cargo metadata: %w", err)
	}
	g, err := depGraphFromMetadataWithScope(raw, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, d.workingDir(req.ProjectPath))
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns))}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) resolveFromLock(req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockRaw, err := os.ReadFile(filepath.Join(workingDir, "Cargo.lock"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Cargo.lock: %w", err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(workingDir, "Cargo.toml"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Cargo.toml: %w", err)
	}
	g, err := depGraphFromLockWithScope(lockRaw, manifestRaw, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns))}, nil
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func depGraphFromMetadata(raw []byte) (*sdk.Graph, error) {
	return depGraphFromMetadataWithScope(raw, sdk.ScopeUnknown)
}

func depGraphFromMetadataWithScope(raw []byte, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	var out metadataOutput
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse cargo metadata: %w", err)
	}
	packagesByID := make(map[string]metadataPackage, len(out.Packages))
	for _, pkg := range out.Packages {
		if strings.TrimSpace(pkg.ID) == "" || strings.TrimSpace(pkg.Name) == "" {
			continue
		}
		packagesByID[pkg.ID] = pkg
	}
	if len(packagesByID) == 0 {
		return nil, fmt.Errorf("cargo metadata does not contain any packages")
	}
	workspace := make(map[string]struct{}, len(out.WorkspaceMembers))
	for _, id := range out.WorkspaceMembers {
		workspace[id] = struct{}{}
	}

	g := sdk.New()
	var root *sdk.Dependency
	if len(workspace) != 1 {
		root = rootNode()
		if err := g.AddNode(root); err != nil {
			return nil, fmt.Errorf("add root node: %w", err)
		}
	}
	for id, pkg := range packagesByID {
		node := packageNode(pkg, id, workspace)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	if root != nil {
		for _, id := range sortedWorkspaceMembers(workspace) {
			pkg, ok := packagesByID[id]
			if !ok {
				continue
			}
			node := packageNode(pkg, id, workspace)
			if err := g.AddEdge(root.ID, node.ID); err != nil {
				return nil, fmt.Errorf("add Cargo workspace root %q: %w", node.ID, err)
			}
		}
	}
	for _, node := range out.Resolve.Nodes {
		parentPkg, ok := packagesByID[node.ID]
		if !ok {
			continue
		}
		parent := packageNode(parentPkg, node.ID, workspace)
		for _, dep := range node.Deps {
			childPkg, ok := packagesByID[dep.Package]
			if !ok {
				continue
			}
			child := packageNode(childPkg, dep.Package, workspace)
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add Cargo dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
			if parent.Type == "application" {
				if existing, ok := g.Node(child.ID); ok {
					existing.AddScope(scopeForDepKinds(dep.DepKinds))
				}
			}
		}
	}
	propagateScopesFromApplicationRoots(g)
	return sdk.FilterGraphByScope(g, scopeFilter)
}

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           "root",
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.PackageTypeApplication,
		Language:       "rust"},
	})

}

func packageNode(pkg metadataPackage, id string, workspace map[string]struct{}) *sdk.Dependency {
	pkgType := "crate"
	if _, ok := workspace[id]; ok {
		pkgType = "application"
	}
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           pkg.Name,
		Version:        pkg.Version,
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.ParsePackageType(pkgType),
		Language:       "rust",
		PURL:           sdk.BuildPackageURL("cargo", "", pkg.Name, pkg.Version)}, ResolvedURL: pkg.Source,
	})

}

func scopeForDepKinds(kinds []metadataDepKind) sdk.Scope {
	for _, kind := range kinds {
		if strings.EqualFold(kind.Kind, "dev") {
			return sdk.ScopeDevelopment
		}
	}
	return sdk.ScopeRuntime
}

func sortedWorkspaceMembers(workspace map[string]struct{}) []string {
	values := make([]string, 0, len(workspace))
	for id := range workspace {
		values = append(values, id)
	}
	sort.Strings(values)
	return values
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

type lockPackage struct {
	Name         string
	Version      string
	Dependencies []string
}

type cargoManifest struct {
	Name            string
	Version         string
	Dependencies    []string
	DevDependencies []string
}

func depGraphFromLock(lockRaw, manifestRaw []byte) (*sdk.Graph, error) {
	return depGraphFromLockWithScope(lockRaw, manifestRaw, sdk.ScopeUnknown)
}

func depGraphFromLockWithScope(lockRaw, manifestRaw []byte, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	packages := parseCargoLockPackages(string(lockRaw))
	if len(packages) == 0 {
		return nil, fmt.Errorf("cargo.lock does not contain any packages")
	}
	manifest := parseCargoManifest(string(manifestRaw))
	if manifest.Name == "" {
		return nil, fmt.Errorf("cargo.toml does not contain a package name")
	}
	g := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           manifest.Name,
		Version:        manifest.Version,
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.PackageTypeApplication,
		Language:       "rust",
		PURL:           sdk.BuildPackageURL("cargo", "", manifest.Name, manifest.Version)},
	})

	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	byName := make(map[string]lockPackage, len(packages))
	for _, pkg := range packages {
		byName[pkg.Name] = pkg
		node := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version}, pkg.Name+"@"+pkg.Version, nil)
		if pkg.Name == manifest.Name {
			continue
		}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	for _, pkg := range packages {
		if pkg.Name == manifest.Name {
			continue
		}
		parent := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version}, pkg.Name+"@"+pkg.Version, nil)
		for _, depName := range pkg.Dependencies {
			childPkg, ok := byName[depName]
			if !ok || childPkg.Name == manifest.Name {
				continue
			}
			child := packageNode(metadataPackage{Name: childPkg.Name, Version: childPkg.Version}, childPkg.Name+"@"+childPkg.Version, nil)
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add Cargo.lock dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}
	for _, depName := range manifest.Dependencies {
		pkg, ok := byName[depName]
		if !ok {
			continue
		}
		node := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version}, pkg.Name+"@"+pkg.Version, nil)
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeRuntime)
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add Cargo root dependency %q: %w", node.ID, err)
		}
	}
	for _, depName := range manifest.DevDependencies {
		pkg, ok := byName[depName]
		if !ok {
			continue
		}
		node := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version}, pkg.Name+"@"+pkg.Version, nil)
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeDevelopment)
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add Cargo dev dependency %q: %w", node.ID, err)
		}
	}

	// BFS: propagate runtime/development scope from direct deps into the transitive tree.
	// Runtime always wins over development.
	directDeps, _ := g.DirectDependencies(root.ID)
	propagateScopes(g, directDeps, root.ID)

	return sdk.FilterGraphByScope(g, scopeFilter)
}

func propagateScopesFromApplicationRoots(g *sdk.Graph) {
	if g == nil {
		return
	}
	for _, root := range g.Nodes() {
		if root == nil || root.Type != "application" {
			continue
		}
		directDeps, err := g.DirectDependencies(root.ID)
		if err != nil {
			continue
		}
		propagateScopes(g, directDeps, root.ID)
	}
}

func propagateScopes(g *sdk.Graph, directDeps []*sdk.Dependency, rootID string) {
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
			dep.AddScope(scope)
		}
		propagated[dep.ID] = scope
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == rootID {
				continue
			}
			nextScope := sdk.MergeScope(propagated[child.ID], scope)
			if nextScope == propagated[child.ID] && child.PrimaryScope() == nextScope {
				continue
			}
			propagated[child.ID] = nextScope
			child.AddScope(nextScope)
			queue = append(queue, child)
		}
	}
}

func parseCargoLockPackages(text string) []lockPackage {
	blocks := strings.Split(text, "\n[[package]]")
	packages := make([]lockPackage, 0, len(blocks))
	for _, block := range blocks {
		lines := strings.Split(block, "\n")
		var pkg lockPackage
		for i := 0; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			switch {
			case strings.HasPrefix(line, "name = "):
				pkg.Name = trimTomlString(strings.TrimPrefix(line, "name = "))
			case strings.HasPrefix(line, "version = "):
				pkg.Version = trimTomlString(strings.TrimPrefix(line, "version = "))
			case strings.HasPrefix(line, "dependencies = ["):
				for i++; i < len(lines); i++ {
					depLine := strings.TrimSpace(strings.TrimSuffix(lines[i], ","))
					if depLine == "]" {
						break
					}
					depLine = trimTomlString(depLine)
					if depLine != "" {
						pkg.Dependencies = append(pkg.Dependencies, strings.Fields(depLine)[0])
					}
				}
			}
		}
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}
	return packages
}

func parseCargoManifest(text string) cargoManifest {
	var manifest cargoManifest
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch section {
		case "package":
			if key == "name" {
				manifest.Name = trimTomlString(value)
			}
			if key == "version" {
				manifest.Version = trimTomlString(value)
			}
		case "dependencies":
			manifest.Dependencies = append(manifest.Dependencies, key)
		case "dev-dependencies":
			manifest.DevDependencies = append(manifest.DevDependencies, key)
		}
	}
	sort.Strings(manifest.Dependencies)
	sort.Strings(manifest.DevDependencies)
	return manifest
}

func trimTomlString(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"`)
}

// Install prepares Cargo dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req sdk.DetectionRequest) error {
	cargoPath, err := cargoExecLookPath("cargo")
	if err != nil {
		return fmt.Errorf("resolve cargo executable: %w", err)
	}
	args := append([]string{"fetch", "--locked"}, req.InstallArgs...)
	cmd := cargoExecCommand(cargoPath, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run cargo fetch: %w", err)
	}
	return nil
}
