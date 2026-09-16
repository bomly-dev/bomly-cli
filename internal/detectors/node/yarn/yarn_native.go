package yarn

import (
	"context"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// NativeDetector resolves dependency graphs with Yarn CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

// PackageManagerSupport returns discovery metadata for the internal Yarn CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerYarn, "package.json").WithMultiModule()}
}

// Ready reports whether Yarn is available.
func (d NativeDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("yarn")
	return detectorkit.CommandNotReadyError("yarn", err)
}

// Applicable reports whether Yarn manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
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
func (d NativeDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameYarnNative,
		RemediationCapabilities: yarnNativeRemediationCapabilities(),
		Technique:               plugin.BuildToolTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerYarn},
		Tags:                    []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Yarn dependency graph via yarn list.
func (d NativeDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "yarn", []string{"list", "--json"}, "Yarn detector", node.DepGraphFromYarnJSON)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachYarnLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs:   model.SingleGraphContainer(depsGraph, detectorkit.InferManifestMetadata(req, yarnManifestMetadataPatterns)),
		Warnings: node.PackageManagerWarnings(d.base().ProjectDir(req.ProjectPath), model.PackageManagerYarn, node.LockfileFormat{}),
	}), nil
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

// Install prepares Yarn dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	return d.base().Install(ctx, req, "yarn", []string{"install"}, "Yarn detector")
}
