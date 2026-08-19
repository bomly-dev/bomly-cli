package swiftpm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
)

// NativeDetector resolves SwiftPM dependency graphs by running
// `swift package show-dependencies --format json`.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns SwiftPM package-manager discovery metadata.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerSwiftPM, evidencePatterns...)}
}

// Ready reports whether the swift binary is available.
func (d NativeDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("swift")
	return detectorkit.CommandNotReadyError("swift", err)
}

// Applicable reports whether SwiftPM files are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return (Detector{WorkingDir: d.workingDir(req.ProjectPath)}).Applicable(ctx, req)
}

// Descriptor describes the SwiftPM native detector.
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSwiftPMNative,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSwift},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSwiftPM},
		Tags:                []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a SwiftPM dependency graph via swift package show-dependencies.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.logger()
	workingDir := d.workingDir(req.ProjectPath)
	executable := "swift"
	args := []string{"package", "show-dependencies", "--format", "json"}

	cmd := system.Command(executable, args...)
	cmd.Dir = workingDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logkit.NewCommandStderr(req.Stderr, req.Verbose)

	started := time.Now()
	logger.Debug("running SwiftPM native detector", logkit.CommandFields(executable, args, workingDir)...)
	if err := cmd.Run(); err != nil {
		logger.Debug("swift package show-dependencies failed", zap.Error(err))
		return sdk.DetectionResult{}, fmt.Errorf("swift package show-dependencies: %w", err)
	}

	g, err := nativeGraph(out.Bytes(), workingDir, logger)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("parse swift show-dependencies output: %w", err)
	}
	logger.Info(fmt.Sprintf("SwiftPM native detector found %d dependencies in %s", g.Size(), logging.FormatDuration(time.Since(started))))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// nativeGraph builds the dependency graph for a native SwiftPM run: the tool's
// own output for structure, and the committed Package.resolved for the commits
// that output omits.
func nativeGraph(raw []byte, workingDir string, logger *zap.Logger) (*sdk.Graph, error) {
	g, err := depGraphFromSwiftShowDeps(raw)
	if err != nil {
		return nil, err
	}
	applyResolvedOrigins(g, workingDir, logger)
	return g, nil
}

// applyResolvedOrigins pins the repositories in a native graph to the commits
// Package.resolved recorded. `swift package show-dependencies` reports a URL
// and a version but no revision, so without this the default path would export
// unpinned repositories while the committed-file fallback exports pinned ones.
//
// Best effort: a project with no readable Package.resolved keeps the origins
// the graph already carries.
func applyResolvedOrigins(g *sdk.Graph, workingDir string, logger *zap.Logger) {
	raw, path, err := readFirstExisting(workingDir, []string{"Package.resolved", ".package.resolved", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"})
	if err != nil || len(raw) == 0 {
		return
	}
	pins, err := parseResolved(raw)
	if err != nil {
		logger.Debug("swiftpm: could not read pins for origin", zap.String("path", path), zap.Error(err))
		return
	}
	if len(pins) == 0 {
		return
	}

	byRepository := make(map[string]swiftPackage, len(pins))
	for _, pin := range pins {
		if key := repositoryKey(pin.Repository); key != "" {
			byRepository[key] = pin
		}
	}

	pinned := 0
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Source != sdk.DependencySourceGit {
			// `swift package edit` replaces a dependency with a local
			// checkout while Package.resolved keeps the pin it replaced.
			// What the build resolved is the truth, so a local node is left
			// alone rather than credited to the repository it stands in for.
			return true
		}
		pin, ok := byRepository[repositoryKey(dep.ResolvedURL)]
		if !ok {
			if pin, ok = pins[dep.Name]; !ok {
				return true
			}
		}
		if pin.Revision == "" || swiftDependencySource(pin.SourceKind, pin.Repository) != sdk.DependencySourceGit {
			return true
		}
		detectors.SetOriginVCS(dep, pin.Repository, pin.Revision)
		pinned++
		return true
	})
	logger.Debug(fmt.Sprintf("swiftpm: pinned %d package origins from %s", pinned, path))
}

// repositoryKey normalizes a repository URL for matching a pin to a graph
// node: SwiftPM reports the same repository with and without a ".git" suffix
// and in either case.
func repositoryKey(repository string) string {
	key := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(repository)), "/"), ".git")
	return key
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

// swiftShowDepsNode is the recursive JSON shape returned by
// `swift package show-dependencies --format json`.
type swiftShowDepsNode struct {
	Name         string              `json:"name"`
	URL          string              `json:"url"`
	Version      string              `json:"version"`
	Dependencies []swiftShowDepsNode `json:"dependencies"`
}

// depGraphFromSwiftShowDeps parses the output of swift package show-dependencies
// and builds a proper transitive dependency graph.
func depGraphFromSwiftShowDeps(raw []byte) (*sdk.Graph, error) {
	// The output may be a single JSON object (the root package) or an array.
	// In practice swift emits a single object.
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty swift package show-dependencies output")
	}

	var tree swiftShowDepsNode
	if err := json.Unmarshal(raw, &tree); err != nil {
		// Try as wrapped {"object": ...} shape just in case
		var wrapped struct {
			Object swiftShowDepsNode `json:"object"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 != nil {
			return nil, fmt.Errorf("parse JSON: %w", err)
		}
		tree = wrapped.Object
	}

	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// seen maps node.ID → true to avoid duplicate AddPackage calls in diamond deps.
	seen := make(map[string]bool)
	if err := buildSwiftDepTree(g, root.ID, tree.Dependencies, seen); err != nil {
		return nil, err
	}
	return g, nil
}

func buildSwiftDepTree(g *sdk.Graph, parentID string, deps []swiftShowDepsNode, seen map[string]bool) error {
	for _, dep := range deps {
		name := dep.Name
		if name == "" {
			name = packageNameFromURL(dep.URL)
		}
		if name == "" {
			continue
		}
		pkg := swiftPackage{
			Name:       name,
			Version:    dep.Version,
			SourceKind: swiftSourceKindForLocation(dep.URL),
			Repository: dep.URL,
		}
		node := packageNode(pkg)

		if !seen[node.ID] {
			seen[node.ID] = true
			if err := addNodeIfMissing(g, node); err != nil {
				return err
			}
		}
		existing, ok := g.Node(node.ID)
		if !ok {
			continue
		}
		if err := g.AddEdge(parentID, existing.ID); err != nil {
			return fmt.Errorf("add SwiftPM dependency %q -> %q: %w", parentID, existing.ID, err)
		}
		// Recurse into transitive deps — only if not already visited.
		if len(dep.Dependencies) > 0 && !seenAllChildren(seen, dep.Dependencies) {
			if err := buildSwiftDepTree(g, existing.ID, dep.Dependencies, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// seenAllChildren reports whether every direct child already has a node in seen.
// Used to short-circuit diamond dependency recursion.
func seenAllChildren(seen map[string]bool, deps []swiftShowDepsNode) bool {
	for _, dep := range deps {
		if dep.Name == "" {
			continue
		}
		if !seen[dep.Name] {
			return false
		}
	}
	return true
}

// Ensure NativeDetector implements FallbackDetector interface.
var _ io.Writer = (*bytes.Buffer)(nil)
