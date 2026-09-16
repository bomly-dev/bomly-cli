package pub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// NativeDetector resolves Dart pub dependency graphs by running `dart pub deps --json`.
// Unlike the lockfile-only Detector, this produces a proper transitive tree with
// parent-child edges from the `dependencies` field of each package record.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

// PackageManagerSupport returns pub package-manager discovery metadata.
func (d NativeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerPub, evidencePatterns...)}
}

// Ready reports whether the dart binary is available.
func (d NativeDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("dart")
	return detectorkit.CommandNotReadyError("dart", err)
}

// Applicable reports whether pub manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	return (Detector{WorkingDir: d.workingDir(req.ProjectPath)}).Applicable(ctx, req)
}

// Descriptor describes the pub native detector.
func (d NativeDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		Name:                detectors.NamePubNative,
		Technique:           plugin.BuildToolTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemDart},
		SupportedManagers:   []model.PackageManager{model.PackageManagerPub},
		Tags:                []string{"graph-resolution", "component-targeting", "scope-annotation"},
	}
}

// ResolveGraph resolves a pub dependency graph via dart pub deps --json.
func (d NativeDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.logger()
	workingDir := d.workingDir(req.ProjectPath)
	executable := "dart"
	args := []string{"pub", "deps", "--json"}

	cmd := system.Command(executable, args...)
	cmd.Dir = workingDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logkit.NewCommandStderr(req.Stderr, req.Verbose)

	started := time.Now()
	logger.Debug("running pub native detector", logkit.CommandFields(executable, args, workingDir)...)
	if err := cmd.Run(); err != nil {
		logger.Debug("dart pub deps failed", zap.Error(err))
		return plugin.DetectionResult{}, fmt.Errorf("dart pub deps: %w", err)
	}

	g, err := nativeGraph(out.Bytes(), workingDir, logger)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("parse dart pub deps output: %w", err)
	}
	logger.Info(fmt.Sprintf("pub native detector found %d dependencies in %s", g.Size(), logging.FormatDuration(time.Since(started))))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs: model.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns)),
	}), nil
}

// nativeGraph builds the dependency graph for a native pub run: the tool's own
// output for structure, and the committed pubspec.lock for the package sources
// that output omits.
func nativeGraph(raw []byte, workingDir string, logger *zap.Logger) (*model.Graph, error) {
	g, err := depGraphFromPubDepsJSON(raw)
	if err != nil {
		return nil, err
	}
	applyLockOrigins(g, workingDir, logger)
	return g, nil
}

// applyLockOrigins records where a native graph's git packages came from.
// `dart pub deps --json` reports a name, version, and kind but not a package's
// source description, so without this the default path would export no origin
// for git dependencies while the committed-file fallback exports the
// repository and the commit pub resolved.
//
// Best effort: a project with no readable pubspec.lock keeps the graph as it is.
func applyLockOrigins(g *model.Graph, workingDir string, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	raw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "pubspec.lock"))
	if err != nil {
		return
	}
	var lock pubLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		logger.Debug("pub: could not read pubspec.lock for origin", zap.Error(err))
		return
	}
	if len(lock.Packages) == 0 {
		return
	}

	recorded := 0
	g.WalkNodes(func(graphNode model.GraphNode) bool {
		dep, isDependency := model.AsDependencyNode(graphNode)
		if !isDependency {
			return true
		}
		if dep.Source != model.DependencySourceGit {
			// An override can point a package at a local path while the lock
			// still describes the git dependency it replaced. What pub
			// resolved for this build is the truth.
			return true
		}
		pkg, ok := lock.Packages[dep.Name]
		if !ok || pubDependencySource(pkg.Source) != model.DependencySourceGit {
			return true
		}
		if origin := model.RepositoryOrigin(descriptionString(pkg.Description, "url"), descriptionString(pkg.Description, "resolved-ref")); origin != nil {
			dep.Origins = model.MergeOrigins(dep.Origins, []model.DependencyOrigin{*origin})
		}
		recorded++
		return true
	})
	logger.Debug(fmt.Sprintf("pub: recorded %d package origins from pubspec.lock", recorded))
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

func (d NativeDetector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func (d NativeDetector) logger() *zap.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return zap.NewNop()
}

// pubDepsJSONPackage represents one entry in the `packages` array from dart pub deps --json.
type pubDepsJSONPackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Kind         string   `json:"kind"` // "root", "direct", "dev", "transitive"
	Source       string   `json:"source"`
	Dependencies []string `json:"dependencies"` // names of immediate deps
}

// pubDepsJSON is the top-level shape of dart pub deps --json output.
type pubDepsJSON struct {
	Root     string               `json:"root"`
	Packages []pubDepsJSONPackage `json:"packages"`
}

// depGraphFromPubDepsJSON parses the output of `dart pub deps --json` and
// builds a dependency graph with proper transitive edges and scope annotation.
//
// Scope mapping:
//   - kind "root"      → root node (unscoped)
//   - kind "direct"    → ScopeRuntime
//   - kind "dev"       → ScopeDevelopment
//   - kind "transitive"→ inherited via BFS propagation
func depGraphFromPubDepsJSON(raw []byte) (*model.Graph, error) {
	var output pubDepsJSON
	if err := json.Unmarshal(raw, &output); err != nil {
		return nil, fmt.Errorf("parse pub deps JSON: %w", err)
	}

	// Build an index by name.
	byName := make(map[string]*pubDepsJSONPackage, len(output.Packages))
	for i := range output.Packages {
		p := &output.Packages[i]
		byName[p.Name] = p
	}

	// Locate the root package.
	rootEntry := byName[output.Root]
	if rootEntry == nil && len(output.Packages) > 0 {
		for i := range output.Packages {
			if output.Packages[i].Kind == "root" {
				rootEntry = &output.Packages[i]
				break
			}
		}
	}

	g := model.New()

	var (
		rootPkg *model.ModuleNode
		err     error
	)
	if rootEntry != nil {
		rootPkg, err = model.NewModuleNode("pubspec.yaml", model.Coordinates{
			Ecosystem:      model.EcosystemDart,
			Name:           rootEntry.Name,
			Version:        rootEntry.Version,
			PackageManager: model.PackageManagerPub,
			Type:           model.PackageTypeApplication,
			Language:       "dart",
		})
	} else {
		rootPkg, err = rootNode(pubspec{})
	}
	if err != nil {
		return nil, fmt.Errorf("build root node: %w", err)
	}
	if err := g.AddNode(rootPkg); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// Add all non-root package nodes with initial scope from kind.
	nodeByName := make(map[string]model.GraphNode, len(output.Packages))
	for i := range output.Packages {
		p := &output.Packages[i]
		if p.Kind == "root" {
			nodeByName[p.Name] = rootPkg
			continue
		}
		lockPkg := pubLockPackage{
			Version: p.Version,
			Source:  p.Source,
		}
		node, err := packageNode(p.Name, lockPkg)
		if err != nil {
			return nil, err
		}
		switch p.Kind {
		case "direct":
			node.AddScope(model.ScopeRuntime)
		case "dev":
			node.AddScope(model.ScopeDevelopment)
		}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		nodeByName[p.Name] = node
	}

	// Wire edges: root → direct/dev deps, then each package → its dependency names.
	for i := range output.Packages {
		p := &output.Packages[i]
		parent := nodeByName[p.Name]
		if parent == nil {
			continue
		}
		for _, depName := range p.Dependencies {
			child := nodeByName[depName]
			if child == nil || child.NodeID() == parent.NodeID() {
				continue
			}
			if err := g.AddEdge(parent.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add pub dep %q -> %q: %w", parent.NodeID(), child.NodeID(), err)
			}
		}
	}

	// Connect any orphan non-root packages to root.
	for _, node := range nodeByName {
		if node == nil || node.NodeID() == rootPkg.NodeID() {
			continue
		}
		dependents, _ := g.Dependents(node.NodeID())
		if len(dependents) == 0 {
			_ = g.AddEdge(rootPkg.NodeID(), node.NodeID())
		}
	}

	// BFS scope propagation: runtime beats development.
	directDepsNodes, _ := g.DirectDependencies(rootPkg.NodeID())
	directDeps := model.DependencyNodesOf(directDepsNodes)
	propagated := make(map[string]model.Scope, g.Size())
	queue := make([]*model.DependencyNode, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == model.ScopeUnknown {
			scope = model.ScopeRuntime
		}
		propagated[dep.NodeID()] = model.MergeScope(propagated[dep.NodeID()], scope)
		dep.AddScope(propagated[dep.NodeID()])
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.NodeID()]
		if scope == model.ScopeUnknown {
			continue
		}
		childrenNodes, err := g.DirectDependencies(current.NodeID())
		children := model.DependencyNodesOf(childrenNodes)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.NodeID() == rootPkg.NodeID() {
				continue
			}
			next := model.MergeScope(propagated[child.NodeID()], scope)
			if next == propagated[child.NodeID()] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.NodeID()] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}
	// Default unscoped non-root packages to runtime.
	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && pkg.NodeID() != rootPkg.NodeID() && pkg.PrimaryScope() == model.ScopeUnknown {
			pkg.AddScope(model.ScopeRuntime)
		}
	}

	return g, nil
}
