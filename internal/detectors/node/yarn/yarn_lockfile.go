package yarn

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

// LockfileDetector resolves dependency graphs with Yarn.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var yarnEvidencePatterns = []string{"yarn.lock"}
var yarnManifestMetadataPatterns = []string{"yarn.lock", "package.json"}

// PackageManagerSupport returns Yarn package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerYarn, yarnEvidencePatterns...)}
}

// Ready reports whether Yarn is available.
func (d LockfileDetector) Ready() bool {
	return true
}

// Applicable reports whether a Yarn lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "yarn.lock"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the Yarn detector.
func (d LockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameYarn,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerYarn},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Yarn dependency graph from yarn.lock.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	depsGraph, err := depGraphFromYarnLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("yarn lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachYarnLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, yarnManifestMetadataPatterns)),
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

// Install prepares Yarn dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	installer, ok := d.Fallback.(sdk.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
