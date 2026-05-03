package pnpm

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// LockfileDetector resolves dependency graphs with pnpm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var pnpmEvidencePatterns = []string{"pnpm-lock.yaml"}
var pnpmManifestMetadataPatterns = []string{"pnpm-lock.yaml", "package.json"}

// PackageManagerSupport returns pnpm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerPNPM, pnpmEvidencePatterns...)}
}

// Ready reports whether pnpm is available.
func (d LockfileDetector) Ready() bool {
	return true
}

// Applicable reports whether a pnpm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "pnpm-lock.yaml"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the pnpm detector.
func (d LockfileDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                 detectors.NamePNPM,
		Enabled:              true,
		ComponentType:        model.LockfileParserComponent,
		SupportedEcosystems:  []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:    []model.PackageManager{model.PackageManagerPNPM},
		SupportedModes:       []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a pnpm dependency graph from pnpm-lock.yaml.
func (d LockfileDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	depsGraph, err := depGraphFromPNPMLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pnpmManifestMetadataPatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares pnpm dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	installer, ok := d.Fallback.(model.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
