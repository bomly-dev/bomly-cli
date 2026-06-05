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
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPNPM, pnpmEvidencePatterns...)}
}

// Ready reports whether pnpm is available.
func (d LockfileDetector) Ready() bool {
	return true
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
		Name:                 detectors.NamePNPM,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPNPM},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a pnpm dependency graph from pnpm-lock.yaml.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	depsGraph, err := depGraphFromPNPMLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pnpm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPnpmLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pnpmManifestMetadataPatterns)),
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
