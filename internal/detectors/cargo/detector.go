package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
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
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerCargo, evidencePatterns...).WithMultiModule()}
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
		IgnoredDirectories:      []string{"target"},
		Name:                    detectors.NameCargo,
		RemediationCapabilities: cargoRemediationCapabilities(),
		Technique:               sdk.LockfileTechnique,
		SupportedEcosystems:     []sdk.Ecosystem{sdk.EcosystemRust},
		SupportedManagers:       []sdk.PackageManager{sdk.PackageManagerCargo},
		Tags:                    []string{"graph-resolution", "component-targeting", "module-graph", "scope-annotation"},
		SupportsInstallFirst:    true,
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
		if commandStderr.ByteCount() > 0 {
			fields = append(fields, zap.Int64("stderr_bytes", commandStderr.ByteCount()))
		}
		logger.Debug("cargo detector failure details", fields...)
		return sdk.DetectionResult{}, fmt.Errorf("run cargo metadata: %w", err)
	}
	return d.detectionResultFromMetadata(req, raw)
}

// detectionResultFromMetadata builds the detection result from cargo metadata
// output: a single entry for single-package projects, one manifest entry per
// workspace member otherwise.
func (d Detector) detectionResultFromMetadata(req sdk.DetectionRequest, raw []byte) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	g, members, err := metadataGraphWithMembers(raw, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	rootManifest := detectorkit.InferManifestMetadata(req, evidencePatterns)
	if len(members) <= 1 {
		return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, rootManifest)}, nil
	}
	modules := make([]cargoModuleGraph, 0, len(members))
	for _, member := range members {
		dir := "."
		if member.manifestPath != "" {
			if rel, err := filepath.Rel(workingDir, filepath.Dir(member.manifestPath)); err == nil && !strings.HasPrefix(filepath.ToSlash(rel), "../") {
				dir = filepath.ToSlash(rel)
			}
		}
		modules = append(modules, cargoModuleGraph{dir: dir, rootID: member.nodeID})
	}
	result, err := cargoDetectionResultFromGraph(g, modules, rootManifest)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger.Info("cargo detector resolved workspace members", zap.Int("members", len(modules)))
	return result, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) resolveFromLock(req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockRaw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "Cargo.lock"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Cargo.lock: %w", err)
	}
	manifestRaw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "Cargo.toml"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Cargo.toml: %w", err)
	}

	// Workspace manifests need member-aware resolution: the plain lock path
	// reads only the root [package] and errors on virtual workspace roots.
	if patterns := parseCargoWorkspaceMembers(string(manifestRaw)); len(patterns) > 0 {
		if memberDirs := expandCargoWorkspaceMemberDirs(workingDir, patterns); len(memberDirs) > 0 {
			return d.resolveLockWorkspace(req, workingDir, lockRaw, manifestRaw, memberDirs)
		}
	}

	g, err := depGraphFromLockWithScope(lockRaw, manifestRaw, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns))}, nil
}

// resolveLockWorkspace resolves a workspace whose root carries a Cargo.lock.
// When cargo is available it prefers `cargo metadata --locked` (deterministic
// given the lock, and richer: resolved dep kinds, exact member manifest
// paths). Without cargo it parses each member Cargo.toml and partitions the
// lock graph by member package names — this also fixes virtual workspace
// roots (workspace-only Cargo.toml), which previously failed with
// "cargo.toml does not contain a package name".
func (d Detector) resolveLockWorkspace(req sdk.DetectionRequest, workingDir string, lockRaw, manifestRaw []byte, memberDirs []string) (sdk.DetectionResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if cargoPath, err := cargoExecLookPath("cargo"); err == nil {
		args := []string{"metadata", "--format-version", "1", "--locked"}
		cmd := cargoExecCommand(cargoPath, args...)
		cmd.Dir = workingDir
		commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
		cmd.Stderr = commandStderr
		logger.Debug("running cargo detector for workspace lock", zap.String("working_dir", cmd.Dir), zap.String("executable", cargoPath), zap.Strings("args", args))
		if raw, err := cmd.Output(); err == nil {
			return d.detectionResultFromMetadata(req, raw)
		}
		logger.Warn("cargo metadata failed for workspace lock; falling back to lockfile partitioning", zap.String("working_dir", workingDir))
	}

	workspaceVersion := parseCargoWorkspaceInheritedVersion(string(manifestRaw))
	rootManifest := applyWorkspaceVersion(parseCargoManifest(string(manifestRaw)), workspaceVersion)
	members := readCargoLockMembers(workingDir, memberDirs, workspaceVersion)
	if len(members) == 0 {
		return sdk.DetectionResult{}, fmt.Errorf("cargo workspace members declared in Cargo.toml could not be read")
	}
	g, modules, rootID, err := depGraphFromLockWorkspace(lockRaw, rootManifest, members, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	if rootID != "" {
		modules = append([]cargoModuleGraph{{dir: ".", rootID: rootID}}, modules...)
	}
	result, err := cargoDetectionResultFromGraph(g, modules, detectorkit.InferManifestMetadata(req, evidencePatterns))
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	logger.Info("cargo detector resolved workspace members from lockfile", zap.Int("members", len(members)))
	return result, nil
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
	g, _, err := metadataGraphWithMembers(raw, scopeFilter)
	return g, err
}

// metadataMember identifies one workspace member in cargo metadata output:
// its node in the resolved graph and the absolute path of its Cargo.toml.
type metadataMember struct {
	nodeID       string
	manifestPath string
}

func metadataGraphWithMembers(raw []byte, scopeFilter sdk.Scope) (*sdk.Graph, []metadataMember, error) {
	var out metadataOutput
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("parse cargo metadata: %w", err)
	}
	packagesByID := make(map[string]metadataPackage, len(out.Packages))
	for _, pkg := range out.Packages {
		if strings.TrimSpace(pkg.ID) == "" || strings.TrimSpace(pkg.Name) == "" {
			continue
		}
		packagesByID[pkg.ID] = pkg
	}
	if len(packagesByID) == 0 {
		return nil, nil, fmt.Errorf("cargo metadata does not contain any packages")
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
			return nil, nil, fmt.Errorf("add root node: %w", err)
		}
	}
	// Cargo's package IDs are source-qualified, so two records sharing a
	// name and version are still distinguishable occurrences. When their
	// origins contradict, both stay as distinct nodes -- the second under a
	// source-qualified ID -- and the resolve section's edges attach each
	// parent to the exact occurrence it depends on via this map.
	nodeIDByCargoID := make(map[string]string, len(packagesByID))
	insert := func(id string) error {
		pkg := packagesByID[id]
		node := packageNode(pkg, id, workspace)
		// Distinct cargo package IDs with different sources are two
		// resolutions of one name@version; the shared helper keeps both.
		surviving, err := detectors.EnsureOccurrence(g, node, strings.TrimSpace(pkg.Source))
		if err != nil {
			return err
		}
		nodeIDByCargoID[id] = surviving.ID
		return nil
	}
	// Workspace members insert first: when an external record collides with a
	// member at one name@version, the project's own package keeps the plain
	// node ID and the external record becomes the qualified occurrence, not
	// the other way around by accident of sort order.
	for _, id := range sortedWorkspaceMembers(workspace) {
		if _, ok := packagesByID[id]; !ok {
			continue
		}
		if err := insert(id); err != nil {
			return nil, nil, err
		}
	}
	for _, id := range sortedPackageIDs(packagesByID) {
		if _, ok := workspace[id]; ok {
			continue
		}
		if err := insert(id); err != nil {
			return nil, nil, err
		}
	}
	idFor := func(cargoID string, pkg metadataPackage) string {
		if nodeID, ok := nodeIDByCargoID[cargoID]; ok {
			return nodeID
		}
		return packageNode(pkg, cargoID, workspace).ID
	}
	members := make([]metadataMember, 0, len(workspace))
	for _, id := range sortedWorkspaceMembers(workspace) {
		pkg, ok := packagesByID[id]
		if !ok {
			continue
		}
		members = append(members, metadataMember{nodeID: idFor(id, pkg), manifestPath: pkg.ManifestPath})
	}
	if root != nil {
		for _, id := range sortedWorkspaceMembers(workspace) {
			pkg, ok := packagesByID[id]
			if !ok {
				continue
			}
			nodeID := idFor(id, pkg)
			if err := g.AddEdge(root.ID, nodeID); err != nil {
				return nil, nil, fmt.Errorf("add Cargo workspace root %q: %w", nodeID, err)
			}
		}
	}
	for _, node := range out.Resolve.Nodes {
		parentPkg, ok := packagesByID[node.ID]
		if !ok {
			continue
		}
		parentID := idFor(node.ID, parentPkg)
		for _, dep := range node.Deps {
			childPkg, ok := packagesByID[dep.Package]
			if !ok {
				continue
			}
			childID := idFor(dep.Package, childPkg)
			if err := g.AddEdge(parentID, childID); err != nil {
				return nil, nil, fmt.Errorf("add Cargo dependency %q -> %q: %w", parentID, childID, err)
			}
			if parentNode, ok := g.Node(parentID); ok && parentNode.Type == "application" {
				if existing, ok := g.Node(childID); ok {
					existing.AddScope(scopeForDepKinds(dep.DepKinds))
				}
			}
		}
	}
	propagateScopesFromApplicationRoots(g)
	filtered, err := sdk.FilterGraphByScope(g, scopeFilter)
	if err != nil {
		return nil, nil, err
	}
	return filtered, members, nil
}

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           "root",
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.PackageTypeApplication,
		FirstParty:     true,
		Language:       "rust"},
	})

}

func packageNode(pkg metadataPackage, id string, workspace map[string]struct{}) *sdk.Dependency {
	pkgType := "crate"
	_, workspaceMember := workspace[id]
	source := cargoDependencySource(pkg.Source)
	if workspaceMember {
		pkgType = "application"
		source = sdk.DependencySourceProject
		if len(workspace) > 1 {
			source = sdk.DependencySourceWorkspace
		}
	}
	node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           pkg.Name,
		Version:        pkg.Version,
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.ParsePackageType(pkgType),
		Language:       "rust",
		PURL:           sdk.BuildPackageURL("cargo", "", pkg.Name, pkg.Version)}, Source: source, ResolvedURL: pkg.Source,
	})
	if !workspaceMember {
		// A workspace member is the project's own code: it has no external
		// origin, whatever a same-named lock entry says.
		setCargoOrigin(node, pkg.Source)
	}
	return node

}

func cargoDependencySource(source string) sdk.DependencySource {
	source = strings.TrimSpace(source)
	switch {
	case strings.HasPrefix(source, "registry+"),
		strings.HasPrefix(source, "sparse+"):
		return sdk.DependencySourceRegistry
	case strings.HasPrefix(source, "git+"):
		return sdk.DependencySourceGit
	case source == "":
		return sdk.DependencySourceFile
	default:
		return ""
	}
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

// sortedPackageIDs orders cargo's package map so one lockfile always builds
// the same graph: map iteration would let two records of one crate decide the
// node differently per run.
func sortedPackageIDs(packages map[string]metadataPackage) []string {
	ids := make([]string, 0, len(packages))
	for id := range packages {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	// Cargo can resolve one crate name and version from two sources -- the same
	// crate pulled from two git remotes, say. They share a PURL, so they are
	// one node, and the shared helper settles what that node claims.
	_, err := detectors.EnsureNode(g, node)
	return err
}

type lockPackage struct {
	Name         string
	Version      string
	Source       string
	Dependencies []string
}

type cargoManifest struct {
	Name    string
	Version string
	// VersionInherited marks `version.workspace = true`: the manifest defers
	// its version to the workspace root's [workspace.package] table.
	VersionInherited bool
	Dependencies     []string
	DevDependencies  []string
}

func depGraphFromLock(lockRaw, manifestRaw []byte) (*sdk.Graph, error) {
	return depGraphFromLockWithScope(lockRaw, manifestRaw, sdk.ScopeUnknown)
}

func depGraphFromLockWithScope(lockRaw, manifestRaw []byte, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	packages := parseCargoLockPackages(string(lockRaw))
	if len(packages) == 0 {
		return nil, fmt.Errorf("cargo.lock does not contain any packages")
	}
	// A root-only workspace carries [workspace.package] in this same manifest
	// while its [package] declares `version.workspace = true`; resolve the
	// inheritance here so both lock paths agree on the package's identity.
	manifest := applyWorkspaceVersion(parseCargoManifest(string(manifestRaw)), parseCargoWorkspaceInheritedVersion(string(manifestRaw)))
	if manifest.Name == "" {
		return nil, fmt.Errorf("cargo.toml does not contain a package name")
	}
	g := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemRust,
		Name:           manifest.Name,
		Version:        manifest.Version,
		PackageManager: sdk.PackageManagerCargo,
		Type:           sdk.PackageTypeApplication,
		FirstParty:     true,
		Language:       "rust",
		PURL:           sdk.BuildPackageURL("cargo", "", manifest.Name, manifest.Version)},
	})

	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	rootRecord := projectLockRecord(packages, manifest)
	rootKey := qualifiedLockKey(rootRecord)
	index, err := buildLockIndex(g, packages, rootRecord)
	if err != nil {
		return nil, err
	}
	rootID := root.ID
	for _, pkg := range packages {
		if qualifiedLockKey(pkg) == rootKey {
			continue
		}
		parentID, ok := index.resolve(qualifiedLockKey(pkg))
		if !ok {
			continue
		}
		if parentID == rootID {
			continue
		}
		for _, depName := range pkg.Dependencies {
			childID, ok := index.resolve(depName)
			if !ok || childID == rootID {
				continue
			}
			if err := g.AddEdge(parentID, childID); err != nil {
				return nil, fmt.Errorf("add Cargo.lock dependency %q -> %q: %w", parentID, childID, err)
			}
		}
	}
	// The root's own lock record names each direct dependency at whatever
	// precision disambiguates it; prefer that over the manifest's bare name.
	rootRefs := lockDependencyRefs(rootRecord)
	resolveDirect := func(depName string) (string, bool) {
		if ref, ok := rootRefs[depName]; ok {
			if id, ok := index.resolve(ref); ok {
				return id, true
			}
		}
		return index.resolve(depName)
	}
	for _, depName := range manifest.Dependencies {
		nodeID, ok := resolveDirect(depName)
		if !ok || nodeID == rootID {
			continue
		}
		if existing, ok := g.Node(nodeID); ok {
			existing.AddScope(sdk.ScopeRuntime)
		}
		if err := g.AddEdge(root.ID, nodeID); err != nil {
			return nil, fmt.Errorf("add Cargo root dependency %q: %w", nodeID, err)
		}
	}
	for _, depName := range manifest.DevDependencies {
		nodeID, ok := resolveDirect(depName)
		if !ok || nodeID == rootID {
			continue
		}
		if existing, ok := g.Node(nodeID); ok {
			existing.AddScope(sdk.ScopeDevelopment)
		}
		if err := g.AddEdge(root.ID, nodeID); err != nil {
			return nil, fmt.Errorf("add Cargo dev dependency %q: %w", nodeID, err)
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
			case strings.HasPrefix(line, "source = "):
				pkg.Source = trimTomlString(strings.TrimPrefix(line, "source = "))
			case strings.HasPrefix(line, "dependencies = ["):
				for i++; i < len(lines); i++ {
					depLine := strings.TrimSpace(strings.TrimSuffix(lines[i], ","))
					if depLine == "]" {
						break
					}
					// Keep the whole reference: Cargo.lock qualifies it with a
					// version (and source) exactly when a bare name would be
					// ambiguous, and truncating to the name resolved every
					// reference to whichever same-named record came first.
					depLine = trimTomlString(depLine)
					if depLine != "" {
						pkg.Dependencies = append(pkg.Dependencies, depLine)
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
				// Inline-table form of workspace inheritance:
				// version = { workspace = true }.
				if strings.HasPrefix(value, "{") {
					if strings.Contains(value, "workspace") && strings.Contains(value, "true") {
						manifest.VersionInherited = true
					}
				} else {
					manifest.Version = trimTomlString(value)
				}
			}
			if key == "version.workspace" && trimTomlString(value) == "true" {
				manifest.VersionInherited = true
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

// trimTomlString decodes the string a TOML key's raw right-hand side names,
// tolerating an inline comment after the value ("1.2.3" # release). A basic
// or literal string is read to its closing quote (honoring \" escapes in
// basic strings, whose content is kept verbatim -- the values read here never
// carry escape sequences); a bare value is cut at the comment and trimmed.
// Trimming quotes off the whole remainder instead left the comment glued to
// the value.
func trimTomlString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
		quote := value[0]
		for i := 1; i < len(value); i++ {
			if value[i] == '\\' && quote == '"' {
				i++
				continue
			}
			if value[i] == quote {
				return value[1:i]
			}
		}
		return strings.TrimPrefix(value, string(quote))
	}
	if cut := strings.IndexByte(value, '#'); cut >= 0 {
		value = value[:cut]
	}
	return strings.TrimSpace(value)
}

// Install prepares Cargo dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	cargoPath, err := cargoExecLookPath("cargo")
	if err != nil {
		return fmt.Errorf("resolve cargo executable: %w", err)
	}
	args := append([]string{"fetch", "--locked"}, req.InstallArgs...)
	cmd := cargoExecCommand(cargoPath, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)
	logger.Debug("running cargo detector install-first", logging.CommandFields(cargoPath, args, cmd.Dir)...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run cargo fetch: %w", err)
	}
	return nil
}
