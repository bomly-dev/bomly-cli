package npm

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

// LockfileDetector resolves dependency graphs with npm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var npmEvidencePatterns = []string{"package-lock.json", "package.json"}

// PackageManagerSupport returns npm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerNPM, npmEvidencePatterns...)}
}

// Ready reports whether npm is available.
func (d LockfileDetector) Ready() bool {
	return true
}

// Applicable reports whether an npm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "package-lock.json"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the npm detector.
func (d LockfileDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                 detectors.NameNPM,
		Enabled:              true,
		ComponentType:        model.LockfileParserComponent,
		SupportedEcosystems:  []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:    []model.PackageManager{model.PackageManagerNPM},
		SupportedModes:       []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves an npm dependency graph from package-lock.json.
func (d LockfileDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	depsGraph, err := depGraphFromNPMLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, npmEvidencePatterns)),
	}, nil
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// FallbackDetector returns the configured fallback detector.
func (d LockfileDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

// Install prepares npm dependencies before graph resolution.
func (d LockfileDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	installer, ok := d.Fallback.(model.InstallFirstDetector)
	if !ok {
		return nil
	}
	return installer.Install(ctx, req)
}
