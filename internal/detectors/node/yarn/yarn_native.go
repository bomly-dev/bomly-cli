package yarn

import (
	"context"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NativeDetector resolves dependency graphs with Yarn CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

// PackageManagerSupport returns discovery metadata for the internal Yarn CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return nil
}

// Ready reports whether Yarn is available.
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("yarn")
	return err == nil
}

// Applicable reports whether Yarn manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	for _, name := range []string{"package.json", "yarn.lock"} {
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

// Descriptor describes the Yarn CLI fallback detector.
func (d NativeDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                 detectors.NameYarnNative,
		Enabled:              true,
		ComponentType:        model.NativeComponent,
		SupportedEcosystems:  []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:    []model.PackageManager{model.PackageManagerYarn},
		SupportedModes:       []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Yarn dependency graph via yarn list.
func (d NativeDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "yarn", []string{"list", "--json"}, "Yarn detector", node.DepGraphFromYarnJSON)
	if err != nil {
		return model.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, yarnEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

// Install prepares Yarn dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	return d.base().Install(ctx, req, "yarn", []string{"install"}, "Yarn detector")
}
