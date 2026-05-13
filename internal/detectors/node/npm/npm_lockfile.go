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
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, npmEvidencePatterns...)}
}

// Ready reports whether npm is available.
func (d LockfileDetector) Ready() bool {
	return true
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
		Name:                 detectors.NameNPM,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerNPM},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves an npm dependency graph from package-lock.json.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	depsGraph, err := depGraphFromNPMLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPackageLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, npmManifestMetadataPatterns)),
	}, nil
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
