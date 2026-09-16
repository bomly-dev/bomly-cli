package bun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

var bunEvidencePatterns = []string{"bun.lock", "bun.lockb"}

// LockfileDetector resolves Bun text lockfiles without invoking Bun.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

// PackageManagerSupport returns Bun package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerBun, bunEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether the native parser can be used.
func (d LockfileDetector) Ready(context.Context, plugin.DetectionRequest) error { return nil }

// Applicable reports whether a Bun text or binary lockfile is present.
func (d LockfileDetector) Applicable(_ context.Context, req plugin.DetectionRequest) (bool, error) {
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
func (d LockfileDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameBun,
		RemediationCapabilities: bunLockfileRemediationCapabilities(),
		Technique:               plugin.LockfileTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerBun},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph parses bun.lock and returns one graph entry per workspace.
// Legacy bun.lockb files are deliberately delegated to the configured Syft
// fallback because their binary format is not a stable public contract.
func (d LockfileDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	textLock := filepath.Join(workingDir, "bun.lock")
	if _, err := os.Stat(textLock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if binaryExists, binaryErr := system.FileExists(filepath.Join(workingDir, "bun.lockb")); binaryErr != nil {
				return plugin.DetectionResult{}, fmt.Errorf("inspect bun.lockb: %w", binaryErr)
			} else if binaryExists {
				return plugin.DetectionResult{}, errors.New("bun.lockb requires the Syft fallback; migrate to the text lockfile with `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`")
			}
		}
		return plugin.DetectionResult{}, fmt.Errorf("read bun.lock: %w", err)
	}

	graphs, err := depGraphFromBunLockfile(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NameBun, "bun.lock"); err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}

	rootManifest := model.ManifestMetadata{Path: "bun.lock", Kind: model.ManifestKindBunLock, Resolution: &model.ResolutionMetadata{Method: model.ResolutionMethodLockfile}}
	entries, err := bunWorkspaceGraphEntries(graphs, rootManifest)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("bun lockfile parser detector: %w", err)
	}
	d.Logger.Info("bun lockfile detector resolved graph", zap.Int("packages", graphs.graph.Size()), zap.Int("workspace_members", len(graphs.modules)))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs: &model.GraphContainer{Entries: entries},
		// bun.lock records no format version, so only the declaration-level
		// checks (pinned manager, engines, install gates) apply.
		Warnings: node.PackageManagerWarnings(workingDir, model.PackageManagerBun, node.LockfileFormat{File: "bun.lock"}),
	}), nil
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() plugin.Detector { return d.Fallback }

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

func bunWorkspaceGraphEntries(graphs bunLockfileGraphs, rootManifest model.ManifestMetadata) ([]model.GraphEntry, error) {
	rootGraph, err := detectorkit.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return nil, fmt.Errorf("extract workspace root graph: %w", err)
	}
	entries := []model.GraphEntry{{Graph: rootGraph, Manifest: rootManifest}}
	for _, module := range graphs.modules {
		moduleGraph, err := detectorkit.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return nil, fmt.Errorf("extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, model.GraphEntry{Graph: moduleGraph, Manifest: model.ManifestMetadata{
			Path: filepath.ToSlash(filepath.Join(module.dir, "package.json")), Kind: model.ManifestKindPackageJSON,
			Resolution: &model.ResolutionMetadata{Method: model.ResolutionMethodLockfile},
		}})
	}
	return entries, nil
}
