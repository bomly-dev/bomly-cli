package pub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NativeDetector resolves Dart pub dependency graphs by running `dart pub deps --json`.
// Unlike the lockfile-only Detector, this produces a proper transitive tree with
// parent-child edges from the `dependencies` field of each package record.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns pub package-manager discovery metadata.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPub, evidencePatterns...)}
}

// Ready reports whether the dart binary is available.
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("dart")
	return err == nil
}

// Applicable reports whether pub manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return (Detector{WorkingDir: d.workingDir(req.ProjectPath)}).Applicable(ctx, req)
}

// Descriptor describes the pub native detector.
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NamePubNative,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemDart},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerPub},
		Capabilities:        []string{"graph-resolution", "component-targeting", "scope-annotation"},
	}
}

// ResolveGraph resolves a pub dependency graph via dart pub deps --json.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	logger := d.logger()
	workingDir := d.workingDir(req.ProjectPath)

	cmd := system.Command("dart", "pub", "deps", "--json")
	cmd.Dir = workingDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)

	started := time.Now()
	logger.Debug("running pub native detector", zap.String("working_dir", workingDir))
	if err := cmd.Run(); err != nil {
		logger.Debug("dart pub deps failed", zap.Error(err))
		return sdk.DetectionResult{}, fmt.Errorf("dart pub deps: %w", err)
	}

	g, err := depGraphFromPubDepsJSON(out.Bytes())
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("parse dart pub deps output: %w", err)
	}
	logger.Info(fmt.Sprintf("pub native detector found %d dependencies in %s", g.Size(), logging.FormatDuration(time.Since(started))))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() sdk.Detector {
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
func depGraphFromPubDepsJSON(raw []byte) (*sdk.Graph, error) {
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

	g := sdk.New()

	var rootPkg *sdk.Dependency
	if rootEntry != nil {
		rootPkg = sdk.NewDependency(sdk.Dependency{
			Ecosystem:   string(sdk.EcosystemDart),
			Name:        rootEntry.Name,
			Version:     rootEntry.Version,
			BuildSystem: sdk.PackageManagerPub.Name(),
			Type:        "application",
			Language:    "dart",
		})

	} else {
		rootPkg = rootNode(pubspec{})
	}
	if err := g.AddNode(rootPkg); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// Add all non-root package nodes with initial scope from kind.
	nodeByName := make(map[string]*sdk.Dependency, len(output.Packages))
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
		node := packageNode(p.Name, lockPkg)
		switch p.Kind {
		case "direct":
			node.AddScope(sdk.ScopeRuntime)
		case "dev":
			node.AddScope(sdk.ScopeDevelopment)
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
			if child == nil || child.ID == parent.ID {
				continue
			}
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add pub dep %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	// Connect any orphan non-root packages to root.
	for _, node := range nodeByName {
		if node == nil || node.ID == rootPkg.ID {
			continue
		}
		dependents, _ := g.Dependents(node.ID)
		if len(dependents) == 0 {
			_ = g.AddEdge(rootPkg.ID, node.ID)
		}
	}

	// BFS scope propagation: runtime beats development.
	directDeps, _ := g.DirectDependencies(rootPkg.ID)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.ID] = sdk.MergeScope(propagated[dep.ID], scope)
		dep.AddScope(propagated[dep.ID])
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
			if child == nil || child.ID == rootPkg.ID {
				continue
			}
			next := sdk.MergeScope(propagated[child.ID], scope)
			if next == propagated[child.ID] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.ID] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}
	// Default unscoped non-root packages to runtime.
	for _, pkg := range g.Nodes() {
		if pkg != nil && pkg.ID != rootPkg.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}

	return g, nil
}
