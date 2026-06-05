package swiftpm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
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
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("swift")
	return err == nil
}

// Applicable reports whether SwiftPM files are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return (Detector{WorkingDir: d.workingDir(req.ProjectPath)}).Applicable(ctx, req)
}

// Descriptor describes the SwiftPM native detector.
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSwiftPMNative,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSwift},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSwiftPM},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a SwiftPM dependency graph via swift package show-dependencies.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	logger := d.logger()
	workingDir := d.workingDir(req.ProjectPath)

	cmd := system.Command("swift", "package", "show-dependencies", "--format", "json")
	cmd.Dir = workingDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)

	started := time.Now()
	logger.Debug("running SwiftPM native detector", zap.String("working_dir", workingDir))
	if err := cmd.Run(); err != nil {
		logger.Debug("swift package show-dependencies failed", zap.Error(err))
		return sdk.DetectionResult{}, fmt.Errorf("swift package show-dependencies: %w", err)
	}

	g, err := depGraphFromSwiftShowDeps(out.Bytes())
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("parse swift show-dependencies output: %w", err)
	}
	logger.Info(fmt.Sprintf("SwiftPM native detector found %d dependencies in %s", g.Size(), logging.FormatDuration(time.Since(started))))
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
