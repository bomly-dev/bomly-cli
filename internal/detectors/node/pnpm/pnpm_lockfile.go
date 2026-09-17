package pnpm

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// LockfileDetector resolves dependency graphs with pnpm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

var pnpmEvidencePatterns = []string{"pnpm-lock.yaml"}
var pnpmManifestMetadataPatterns = []string{"pnpm-lock.yaml", "package.json"}

// PackageManagerSupport returns pnpm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerPNPM, pnpmEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether pnpm is available.
func (d LockfileDetector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether a pnpm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "pnpm-lock.yaml"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the pnpm detector.
func (d LockfileDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NamePNPMLockfile,
		RemediationCapabilities: pnpmLockfileRemediationCapabilities(),
		Technique:               plugin.LockfileTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerPNPM},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a pnpm dependency graph from pnpm-lock.yaml. A
// workspace lockfile yields one manifest entry per workspace importer (the
// member's package.json plus its reachable dependency subtree) alongside the
// root entry.
func (d LockfileDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	graphs, err := depGraphFromPNPMLockfile(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NamePNPMLockfile, "pnpm-lock.yaml"); err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(workingDir, graphs.graph); err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachPnpmLockPositions(graphs.graph, workingDir)

	rootManifest := detectorkit.InferManifestMetadata(req, pnpmManifestMetadataPatterns)
	warnings := node.PackageManagerWarnings(workingDir, model.PackageManagerPNPM,
		node.LockfileFormat{File: "pnpm-lock.yaml", Version: graphs.lockfileVersion})
	if len(graphs.modules) == 0 {
		return detectors.Attributed(plugin.DetectionResult{
			Graphs:   model.SingleGraphContainer(graphs.graph, rootManifest),
			Warnings: warnings,
		}), nil
	}

	entries := make([]model.GraphEntry, 0, len(graphs.modules)+1)
	rootGraph, err := detectorkit.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: extract workspace root graph: %w", err)
	}
	entries = append(entries, model.GraphEntry{Graph: rootGraph, Manifest: rootManifest})
	for _, module := range graphs.modules {
		moduleGraph, err := detectorkit.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return plugin.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, model.GraphEntry{
			Graph: moduleGraph,
			Manifest: model.ManifestMetadata{
				Path: module.dir + "/package.json",
				Kind: model.ManifestKind("package.json"),
			},
		})
	}
	req.DetectorLogger(d.Logger).Info("pnpm lockfile detector resolved workspace members",
		zap.Int("members", len(graphs.modules)))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs:   &model.GraphContainer{Entries: entries},
		Warnings: warnings,
	}), nil
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}
