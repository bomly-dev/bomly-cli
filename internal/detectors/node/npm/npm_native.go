package npm

import (
	"context"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NPMNativeDetector resolves dependency graphs with npm CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

// PackageManagerSupport returns discovery metadata for the internal npm CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return nil
}

// Ready reports whether npm is available.
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("npm")
	return err == nil
}

// Applicable reports whether npm manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	for _, name := range []string{"package.json", "package-lock.json"} {
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

// Descriptor describes the npm CLI fallback detector.
func (d NativeDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                 detectors.NameNPMNative,
		Enabled:              true,
		ComponentType:        model.NativeComponent,
		SupportedEcosystems:  []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:    []model.PackageManager{model.PackageManagerNPM},
		SupportedModes:       []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves an npm dependency graph via npm ls.
func (d NativeDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "npm", []string{"ls", "--all", "--json", "--package-lock-only"}, "NPM detector", node.DepGraphFromNPMJSON)
	if err != nil {
		return model.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, npmEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

// Install prepares npm dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	return d.base().Install(ctx, req, "npm", []string{"i"}, "NPM detector")
}
