package bun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var bunEvidencePatterns = []string{"bun.lock", "bun.lockb"}

// LockfileDetector resolves Bun text lockfiles without invoking Bun.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns Bun package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerBun, bunEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether the native parser can be used.
func (d LockfileDetector) Ready(context.Context, sdk.DetectionRequest) error { return nil }

// Applicable reports whether a Bun text or binary lockfile is present.
func (d LockfileDetector) Applicable(_ context.Context, req sdk.DetectionRequest) (bool, error) {
	workingDir := d.base().ProjectDir(req.ProjectPath)
	for _, name := range bunEvidencePatterns {
		exists, err := system.FileExists(filepath.Join(workingDir, name))
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the Bun lockfile detector.
func (d LockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:  []string{"node_modules", "dist"},
		Name:                detectors.NameBun,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerBun},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph parses bun.lock and returns one graph entry per workspace.
// Legacy bun.lockb files are deliberately delegated to the configured Syft
// fallback because their binary format is not a stable public contract.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	textLock := filepath.Join(workingDir, "bun.lock")
	if _, err := os.Stat(textLock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if binaryExists, binaryErr := system.FileExists(filepath.Join(workingDir, "bun.lockb")); binaryErr != nil {
				return sdk.DetectionResult{}, fmt.Errorf("inspect bun.lockb: %w", binaryErr)
			} else if binaryExists {
				return sdk.DetectionResult{}, errors.New("bun.lockb requires the Syft fallback; migrate to the text lockfile with `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`")
			}
		}
		return sdk.DetectionResult{}, fmt.Errorf("read bun.lock: %w", err)
	}

	graphs, err := depGraphFromBunLockfile(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NameBun, "bun.lock"); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}

	rootManifest := sdk.ManifestMetadata{Path: "bun.lock", Kind: sdk.ManifestKindBunLock, Resolution: &sdk.ResolutionMetadata{Method: sdk.ResolutionMethodLockfile}}
	entries, err := bunWorkspaceGraphEntries(graphs, rootManifest)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}
	d.Logger.Info("bun lockfile detector resolved graph", zap.Int("packages", graphs.graph.Size()), zap.Int("workspace_members", len(graphs.modules)))
	return sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: entries}}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() sdk.Detector { return d.Fallback }

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

func bunWorkspaceGraphEntries(graphs bunLockfileGraphs, rootManifest sdk.ManifestMetadata) ([]sdk.GraphEntry, error) {
	rootGraph, err := detectors.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return nil, fmt.Errorf("extract workspace root graph: %w", err)
	}
	entries := []sdk.GraphEntry{{Graph: rootGraph, Manifest: rootManifest}}
	for _, module := range graphs.modules {
		moduleGraph, err := detectors.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return nil, fmt.Errorf("extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, sdk.GraphEntry{Graph: moduleGraph, Manifest: sdk.ManifestMetadata{
			Path: filepath.ToSlash(filepath.Join(module.dir, "package.json")), Kind: sdk.ManifestKindPackageJSON,
			Resolution: &sdk.ResolutionMetadata{Method: sdk.ResolutionMethodLockfile},
		}})
	}
	return entries, nil
}
