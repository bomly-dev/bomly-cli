package yarn

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

// LockfileDetector resolves dependency graphs with Yarn.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var yarnEvidencePatterns = []string{"yarn.lock", "package.json"}

// PackageManagerSupport returns Yarn package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerYarn, yarnEvidencePatterns...)}
}

// Ready reports whether Yarn is available.
func (d LockfileDetector) Ready() bool {
	return true
}

// Applicable reports whether a Yarn lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "yarn.lock"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the Yarn detector.
func (d LockfileDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                 detectors.NameYarn,
		Enabled:              true,
		ComponentType:        model.LockfileParserComponent,
		SupportedEcosystems:  []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:    []model.PackageManager{model.PackageManagerYarn},
		SupportedModes:       []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Yarn dependency graph from yarn.lock.
func (d LockfileDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	depsGraph, err := depGraphFromYarnLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("yarn lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, yarnEvidencePatterns)),
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

// Install prepares Yarn dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	installer, ok := d.Fallback.(model.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
