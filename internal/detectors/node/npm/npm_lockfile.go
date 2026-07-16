package npm

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// LockfileDetector resolves dependency graphs with npm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var npmEvidencePatterns = []string{"package-lock.json"}
var npmManifestMetadataPatterns = []string{"package-lock.json", "package.json"}

// PackageManagerSupport returns npm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, npmEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether npm is available.
func (d LockfileDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether an npm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "package-lock.json"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the npm detector.
func (d LockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:   []string{"node_modules", "dist"},
		Name:                 detectors.NameNPM,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerNPM},
		Tags:                 []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves an npm dependency graph from package-lock.json. A
// workspace lockfile yields one manifest entry per workspace member (the
// member's package.json plus its reachable dependency subtree) alongside the
// root entry.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	graphs, err := depGraphFromNPMLockfile(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NameNPM, "package-lock.json"); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(workingDir, graphs.graph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPackageLockPositions(graphs.graph, workingDir)

	rootManifest := detectors.InferManifestMetadata(req, npmManifestMetadataPatterns)
	if len(graphs.modules) == 0 {
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(graphs.graph, rootManifest),
		}, nil
	}

	entries, err := workspaceGraphEntries(graphs, rootManifest)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	req.DetectorLogger(d.Logger).Info("npm lockfile detector resolved workspace members",
		zap.Int("members", len(graphs.modules)))
	return sdk.DetectionResult{
		Graphs: &sdk.GraphContainer{Entries: entries},
	}, nil
}

// workspaceGraphEntries partitions a workspace lockfile graph into the root
// manifest entry (root node plus its own dependency subtree) and one entry
// per workspace member (member root plus its reachable subtree, manifest
// path "<member-dir>/package.json").
func workspaceGraphEntries(graphs npmLockfileGraphs, rootManifest sdk.ManifestMetadata) ([]sdk.GraphEntry, error) {
	entries := make([]sdk.GraphEntry, 0, len(graphs.modules)+1)
	rootGraph, err := detectors.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return nil, fmt.Errorf("extract workspace root graph: %w", err)
	}
	entries = append(entries, sdk.GraphEntry{Graph: rootGraph, Manifest: rootManifest})
	for _, module := range graphs.modules {
		moduleGraph, err := detectors.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return nil, fmt.Errorf("extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, sdk.GraphEntry{
			Graph: moduleGraph,
			Manifest: sdk.ManifestMetadata{
				Path: module.dir + "/package.json",
				Kind: sdk.ManifestKind("package.json"),
			},
		})
	}
	return entries, nil
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

// Install prepares npm dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	installer, ok := d.Fallback.(sdk.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
