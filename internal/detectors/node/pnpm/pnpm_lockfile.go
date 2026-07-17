package pnpm

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

// LockfileDetector resolves dependency graphs with pnpm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var pnpmEvidencePatterns = []string{"pnpm-lock.yaml"}
var pnpmManifestMetadataPatterns = []string{"pnpm-lock.yaml", "package.json"}

// PackageManagerSupport returns pnpm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPNPM, pnpmEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether pnpm is available.
func (d LockfileDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether a pnpm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "pnpm-lock.yaml"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the pnpm detector.
func (d LockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:   []string{"node_modules", "dist"},
		Name:                 detectors.NamePNPM,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPNPM},
		Tags:                 []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a pnpm dependency graph from pnpm-lock.yaml. A
// workspace lockfile yields one manifest entry per workspace importer (the
// member's package.json plus its reachable dependency subtree) alongside the
// root entry.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	graphs, err := depGraphFromPNPMLockfile(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NamePNPM, "pnpm-lock.yaml"); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(workingDir, graphs.graph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPnpmLockPositions(graphs.graph, workingDir)

	rootManifest := detectors.InferManifestMetadata(req, pnpmManifestMetadataPatterns)
	if len(graphs.modules) == 0 {
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(graphs.graph, rootManifest),
		}, nil
	}

	entries := make([]sdk.GraphEntry, 0, len(graphs.modules)+1)
	rootGraph, err := detectors.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: extract workspace root graph: %w", err)
	}
	entries = append(entries, sdk.GraphEntry{Graph: rootGraph, Manifest: rootManifest})
	for _, module := range graphs.modules {
		moduleGraph, err := detectors.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return sdk.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, sdk.GraphEntry{
			Graph: moduleGraph,
			Manifest: sdk.ManifestMetadata{
				Path: module.dir + "/package.json",
				Kind: sdk.ManifestKind("package.json"),
			},
		})
	}
	req.DetectorLogger(d.Logger).Info("pnpm lockfile detector resolved workspace members",
		zap.Int("members", len(graphs.modules)))
	return sdk.DetectionResult{
		Graphs: &sdk.GraphContainer{Entries: entries},
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares pnpm dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	installer, ok := d.Fallback.(sdk.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
