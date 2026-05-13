package npm

import (
	"context"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NPMNativeDetector resolves dependency graphs with npm CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns discovery metadata for the internal npm CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, "package.json")}
}

// Ready reports whether npm is available.
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("npm")
	return err == nil
}

// Applicable reports whether npm manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
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
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameNPMNative,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerNPM},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves an npm dependency graph via npm ls.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "npm", []string{"ls", "--all", "--json", "--package-lock-only"}, "NPM detector", node.DepGraphFromNPMJSON)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPackageLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, npmManifestMetadataPatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

// Install prepares npm dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().Install(ctx, req, "npm", []string{"i"}, "NPM detector")
}
