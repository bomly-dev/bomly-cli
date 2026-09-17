package npm

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

// NativeDetector resolves dependency graphs with npm CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

// PackageManagerSupport returns discovery metadata for the internal npm CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, "package.json").WithMultiModule()}
}

// Ready reports whether npm is available.
func (d NativeDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("npm")
	return detectorkit.CommandNotReadyError("npm", err)
}

// Applicable reports whether npm manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
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
func (d NativeDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameNPMNative,
		RemediationCapabilities: npmNativeRemediationCapabilities(),
		Technique:               plugin.BuildToolTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerNPM},
		Tags:                    []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves an npm dependency graph via npm ls.
func (d NativeDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "npm", npmListArgs(req.ScopeFilter), "NPM detector", node.DepGraphFromNPMJSON)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachPackageLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs:   model.SingleGraphContainer(depsGraph, detectorkit.InferManifestMetadata(req, npmManifestMetadataPatterns)),
		Warnings: node.PackageManagerWarnings(d.base().ProjectDir(req.ProjectPath), model.PackageManagerNPM, node.LockfileFormat{}),
	}), nil
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

func npmListArgs(scope model.Scope) []string {
	args := []string{"ls", "--all", "--json", "--package-lock-only"}
	if scope == model.ScopeRuntime {
		args = append(args, "--omit=dev")
	}
	return args
}

// Install prepares npm dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	return d.base().Install(ctx, req, "npm", []string{"i"}, "NPM detector")
}
