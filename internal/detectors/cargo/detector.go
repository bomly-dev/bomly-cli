package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

var cargoExecLookPath = system.LookPath
var cargoExecCommand = system.Command

// Detector resolves Rust dependency graphs through cargo metadata.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

var evidencePatterns = []string{"Cargo.lock", "Cargo.toml"}

type metadataOutput struct {
	Packages         []metadataPackage `json:"packages"`
	Resolve          metadataResolve   `json:"resolve"`
	WorkspaceMembers []string          `json:"workspace_members"`
	// WorkspaceRoot is the absolute directory cargo resolved the workspace
	// from. It is what makes a member's manifest_path expressible as the
	// repo-relative path a module ID needs.
	WorkspaceRoot string `json:"workspace_root"`
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
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerCargo, evidencePatterns...).WithMultiModule()}
}

// Ready reports whether Cargo is available.
func (d Detector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether Cargo manifests are present.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	return system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Cargo.toml"))
}

// Descriptor describes the Cargo detector.
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"target"},
		Name:                    detectors.NameCargo,
		RemediationCapabilities: cargoRemediationCapabilities(),
		Technique:               plugin.LockfileTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemRust},
		SupportedManagers:       []model.PackageManager{model.PackageManagerCargo},
		Tags:                    []string{"graph-resolution", "component-targeting", "module-graph", "scope-annotation"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Cargo dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if ok, err := system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Cargo.lock")); err != nil {
		return plugin.DetectionResult{}, err
	} else if ok {
		return d.resolveFromLock(req)
	}

	cargoPath, err := cargoExecLookPath("cargo")
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("resolve cargo executable: %w", err)
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
		return plugin.DetectionResult{}, fmt.Errorf("run cargo metadata: %w", err)
	}
	return d.detectionResultFromMetadata(req, raw)
}

// detectionResultFromMetadata builds the detection result from cargo metadata
// output: a single entry for single-package projects, one manifest entry per
// workspace member otherwise.
func (d Detector) detectionResultFromMetadata(req plugin.DetectionRequest, raw []byte) (plugin.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	g, members, err := metadataGraphWithMembers(raw, req.ScopeFilter)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	rootManifest := detectorkit.InferManifestMetadata(req, evidencePatterns)
	if len(members) <= 1 {
		return detectors.Attributed(plugin.DetectionResult{Graphs: model.SingleGraphContainer(g, rootManifest)}), nil
	}
	modules := make([]cargoModuleGraph, 0, len(members))
	for _, member := range members {
		dir := "."
		if member.manifestPath != "" {
			if rel, err := filepath.Rel(workingDir, filepath.Dir(member.manifestPath)); err == nil && !strings.HasPrefix(filepath.ToSlash(rel), "../") {
				dir = filepath.ToSlash(rel)
			}
		}
		// A workspace member is the project's own code, so it becomes a
		// module node declared by its own Cargo.toml. This is the first point
		// that knows the member's directory -- cargo reports an absolute
		// manifest path, and a module ID must be repo-relative -- so the node
		// is promoted here rather than built as a module upstream.
		rootID, err := detectorkit.PromoteToModule(g, member.nodeID, path.Join(dir, "Cargo.toml"))
		if err != nil {
			return plugin.DetectionResult{}, err
		}
		modules = append(modules, cargoModuleGraph{dir: dir, rootID: rootID})
	}
	result, err := cargoDetectionResultFromGraph(g, modules, rootManifest)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger.Info("cargo detector resolved workspace members", zap.Int("members", len(modules)))
	return result, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

func (d Detector) resolveFromLock(req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockRaw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "Cargo.lock"))
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("read Cargo.lock: %w", err)
	}
	manifestRaw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "Cargo.toml"))
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("read Cargo.toml: %w", err)
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
		return plugin.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	return detectors.Attributed(plugin.DetectionResult{Graphs: model.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns))}), nil
}

// resolveLockWorkspace resolves a workspace whose root carries a Cargo.lock.
// When cargo is available it prefers `cargo metadata --locked` (deterministic
// given the lock, and richer: resolved dep kinds, exact member manifest
// paths). Without cargo it parses each member Cargo.toml and partitions the
// lock graph by member package names — this also fixes virtual workspace
// roots (workspace-only Cargo.toml), which previously failed with
// "cargo.toml does not contain a package name".
func (d Detector) resolveLockWorkspace(req plugin.DetectionRequest, workingDir string, lockRaw, manifestRaw []byte, memberDirs []string) (plugin.DetectionResult, error) {
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
		return plugin.DetectionResult{}, fmt.Errorf("cargo workspace members declared in Cargo.toml could not be read")
	}
	g, modules, rootID, err := depGraphFromLockWorkspace(lockRaw, rootManifest, members, req.ScopeFilter)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachCargoLockPositions(g, workingDir)
	if rootID != "" {
		modules = append([]cargoModuleGraph{{dir: ".", rootID: rootID}}, modules...)
	}
	result, err := cargoDetectionResultFromGraph(g, modules, detectorkit.InferManifestMetadata(req, evidencePatterns))
	if err != nil {
		return plugin.DetectionResult{}, err
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

func depGraphFromMetadata(raw []byte) (*model.Graph, error) {
	return depGraphFromMetadataWithScope(raw, model.ScopeUnknown)
}

func depGraphFromMetadataWithScope(raw []byte, scopeFilter model.Scope) (*model.Graph, error) {
	g, _, err := metadataGraphWithMembers(raw, scopeFilter)
	return g, err
}

// metadataMember identifies one workspace member in cargo metadata output:
// its node in the resolved graph and the absolute path of its Cargo.toml.
type metadataMember struct {
	nodeID       string
	manifestPath string
}

func metadataGraphWithMembers(raw []byte, scopeFilter model.Scope) (*model.Graph, []metadataMember, error) {
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

	g := model.New()
	var root *model.ModuleNode
	if len(workspace) != 1 {
		var err error
		root, err = rootNode()
		if err != nil {
			return nil, nil, fmt.Errorf("build cargo root module node: %w", err)
		}
		if err := g.AddNode(root); err != nil {
			return nil, nil, fmt.Errorf("add root node: %w", err)
		}
	}
	// Cargo's package IDs are source-qualified, so two records can share a
	// name and version. They fold into one node under ADR-0041 -- identity is
	// the canonical package URL and cargo PURLs carry no source -- and both
	// sources survive on the node's Origins list. This map still exists
	// because the resolve section's edges are keyed by cargo's IDs, which are
	// not node IDs.
	nodeIDByCargoID := make(map[string]string, len(packagesByID))
	insert := func(id string) error {
		pkg := packagesByID[id]
		node, err := packageNode(pkg, id, workspace, out.WorkspaceRoot)
		if err != nil {
			return err
		}
		// Distinct cargo package IDs with different sources now fold into
		// one node under ADR-0041: identity is the canonical package URL, and
		// cargo PURLs carry no source qualifier. Both sources survive on the
		// node's Origins list rather than as two nodes.
		surviving, err := detectorkit.EnsureNode(g, node)
		if err != nil {
			return err
		}
		nodeIDByCargoID[id] = surviving.NodeID()
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
		// A node that cannot mint an identity has no ID to resolve an edge
		// to; the caller skips the edge rather than inventing one.
		node, err := packageNode(pkg, cargoID, workspace, out.WorkspaceRoot)
		if err != nil {
			return ""
		}
		return node.NodeID()
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
			if err := g.AddEdge(root.NodeID(), nodeID); err != nil {
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
			// A workspace member's direct dependencies take its scope. The
			if parentNode, ok := g.Node(parentID); ok && isCargoProjectRoot(parentNode) {
				if existingNode, ok := g.Node(childID); ok {
					if existing, isDep := model.AsDependencyNode(existingNode); isDep {
						existing.AddScope(scopeForDepKinds(dep.DepKinds))
					}
				}
			}
		}
	}
	propagateScopesFromApplicationRoots(g)
	filtered, err := model.FilterGraphByScope(g, scopeFilter)
	if err != nil {
		return nil, nil, err
	}
	return filtered, members, nil
}

func rootNode() (*model.ModuleNode, error) {
	return model.NewModuleNode("Cargo.toml", model.Coordinates{Ecosystem: model.EcosystemRust,
		Name:           "root",
		PackageManager: model.PackageManagerCargo,
		Type:           model.PackageTypeApplication,
		Language:       "rust"})

}

// cargoModuleManifest returns the repo-relative manifest path that declares a
// workspace member, given the workspace root cargo reported. It falls back to
// the top-level Cargo.toml when the paths do not relate -- a module still
// needs a declaring manifest, and the root one is the honest answer when the
// member's own cannot be expressed relative to the scan.
func cargoModuleManifest(manifestPath, workspaceRoot string) string {
	if manifestPath == "" || workspaceRoot == "" {
		return "Cargo.toml"
	}
	rel, err := filepath.Rel(workspaceRoot, manifestPath)
	if err != nil {
		return "Cargo.toml"
	}
	slashed := filepath.ToSlash(rel)
	if slashed == "" || strings.HasPrefix(slashed, "../") {
		return "Cargo.toml"
	}
	return slashed
}

func packageNode(pkg metadataPackage, id string, workspace map[string]struct{}, workspaceRoot string) (model.GraphNode, error) {
	coords := model.Coordinates{
		Ecosystem:      model.EcosystemRust,
		Name:           pkg.Name,
		Version:        pkg.Version,
		PackageManager: model.PackageManagerCargo,
		Type:           model.ParsePackageType("crate"),
		Language:       "rust",
		PURL:           model.BuildPackageURLFor(model.EcosystemRust, model.PackageManagerCargo, "", pkg.Name, pkg.Version),
	}
	if _, workspaceMember := workspace[id]; workspaceMember {
		// A workspace member is the project's own code, so it is a module
		// node declared by its own Cargo.toml (ADR-0041). It asserts no
		// origin at all, which is the stronger form of the rule the old
		// dependency node needed a guard for: a same-named lock entry cannot
		// credit the project's code to someone else's remote.
		coords.Type = model.PackageTypeApplication
		node, err := model.NewModuleNode(cargoModuleManifest(pkg.ManifestPath, workspaceRoot), coords)
		if err != nil {
			return nil, fmt.Errorf("build cargo module node %q: %w", pkg.Name, err)
		}
		return node, nil
	}
	node, err := model.NewDependencyNode(coords)
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}
	node.Source = cargoDependencySource(pkg.Source)
	node.ResolvedURL = pkg.Source
	setCargoOrigin(node, pkg.Source)
	return node, nil
}

func cargoDependencySource(source string) model.DependencySource {
	source = strings.TrimSpace(source)
	switch {
	case strings.HasPrefix(source, "registry+"),
		strings.HasPrefix(source, "sparse+"):
		return model.DependencySourceRegistry
	case strings.HasPrefix(source, "git+"):
		return model.DependencySourceGit
	case source == "":
		return model.DependencySourceFile
	default:
		return ""
	}
}

func scopeForDepKinds(kinds []metadataDepKind) model.Scope {
	for _, kind := range kinds {
		if strings.EqualFold(kind.Kind, "dev") {
			return model.ScopeDevelopment
		}
	}
	return model.ScopeRuntime
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

func addNodeIfMissing(g *model.Graph, node model.GraphNode) error {
	// Cargo can resolve one crate name and version from two sources -- the same
	// crate pulled from two git remotes, say. They share a PURL, so they are
	// one node, and the shared helper settles what that node claims.
	_, err := detectorkit.EnsureNode(g, node)
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

func depGraphFromLock(lockRaw, manifestRaw []byte) (*model.Graph, error) {
	return depGraphFromLockWithScope(lockRaw, manifestRaw, model.ScopeUnknown)
}

func depGraphFromLockWithScope(lockRaw, manifestRaw []byte, scopeFilter model.Scope) (*model.Graph, error) {
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
	g := model.New()
	root, err := model.NewModuleNode("Cargo.toml", model.Coordinates{Ecosystem: model.EcosystemRust,
		Name:           manifest.Name,
		Version:        manifest.Version,
		PackageManager: model.PackageManagerCargo,
		Type:           model.PackageTypeApplication,
		Language:       "rust",
		PURL:           model.BuildPackageURLFor(model.EcosystemRust, model.PackageManagerCargo, "", manifest.Name, manifest.Version)})
	if err != nil {
		return nil, fmt.Errorf("build root node: %w", err)
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	rootRecord := projectLockRecord(packages, manifest)
	rootKey := qualifiedLockKey(rootRecord)
	index, err := buildLockIndex(g, packages, rootRecord)
	if err != nil {
		return nil, err
	}
	rootID := root.NodeID()
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
		if existingNode, ok := g.Node(nodeID); ok {
			existing, _ := model.AsDependencyNode(existingNode)
			if existing != nil {
				existing.AddScope(model.ScopeRuntime)
			}
			if err := g.AddEdge(root.NodeID(), nodeID); err != nil {
				return nil, fmt.Errorf("add Cargo root dependency %q: %w", nodeID, err)
			}
		}
	}
	for _, depName := range manifest.DevDependencies {
		nodeID, ok := resolveDirect(depName)
		if !ok || nodeID == rootID {
			continue
		}
		if existingNode, ok := g.Node(nodeID); ok {
			existing, _ := model.AsDependencyNode(existingNode)
			if existing != nil {
				existing.AddScope(model.ScopeDevelopment)
			}
			if err := g.AddEdge(root.NodeID(), nodeID); err != nil {
				return nil, fmt.Errorf("add Cargo dev dependency %q: %w", nodeID, err)
			}
		}
	}

	// BFS: propagate runtime/development scope from direct deps into the transitive tree.
	// Runtime always wins over development.
	directDepsNodes, _ := g.DirectDependencies(root.NodeID())
	directDeps := model.DependencyNodesOf(directDepsNodes)
	propagateScopes(g, directDeps, root.NodeID())

	return model.FilterGraphByScope(g, scopeFilter)
}

// isCargoProjectRoot reports whether a node stands for the project's own code.
//
// A workspace member is a module node once the detection-result path has
// promoted it, and an application-typed dependency node before that -- the
// metadata graph is built before the member's directory is known. Both spell
// the same thing, so the predicate accepts either rather than each caller
// picking one and quietly missing the other.
func isCargoProjectRoot(node model.GraphNode) bool {
	if model.IsProjectOwned(node) {
		return true
	}
	dep, ok := model.AsDependencyNode(node)
	return ok && dep.Type == model.PackageTypeApplication
}

func propagateScopesFromApplicationRoots(g *model.Graph) {
	if g == nil {
		return
	}
	// Roots are the project's own artifacts: the module nodes, plus any
	// application-typed dependency node the metadata path has not promoted
	// yet. Reading only dependency nodes lost every propagation once the
	// workspace root became a module.
	roots := make([]model.GraphNode, 0, g.Size())
	for _, node := range g.Nodes() {
		if isCargoProjectRoot(node) {
			roots = append(roots, node)
		}
	}
	for _, root := range roots {
		directDepNodes, err := g.DirectDependencies(root.NodeID())
		directDeps := model.DependencyNodesOf(directDepNodes)
		if err != nil {
			continue
		}
		propagateScopes(g, directDeps, root.NodeID())
	}
}

func propagateScopes(g *model.Graph, directDeps []*model.DependencyNode, rootID string) {
	propagated := make(map[string]model.Scope, g.Size())
	queue := make([]*model.DependencyNode, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == model.ScopeUnknown {
			scope = model.ScopeRuntime
			dep.AddScope(scope)
		}
		propagated[dep.NodeID()] = scope
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.NodeID()]
		if scope == model.ScopeUnknown {
			continue
		}
		childNodes, err := g.DirectDependencies(current.NodeID())
		children := model.DependencyNodesOf(childNodes)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.NodeID() == rootID {
				continue
			}
			nextScope := model.MergeScope(propagated[child.NodeID()], scope)
			if nextScope == propagated[child.NodeID()] && child.PrimaryScope() == nextScope {
				continue
			}
			propagated[child.NodeID()] = nextScope
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
	for rawLine := range strings.SplitSeq(text, "\n") {
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
		case "package.version":
			// Table form of workspace inheritance: [package.version] with
			// workspace = true.
			if key == "workspace" && trimTomlString(value) == "true" {
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
func (d Detector) Install(_ context.Context, req plugin.DetectionRequest) error {
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
