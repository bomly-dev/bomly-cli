package pnpm

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

// NativeDetector resolves dependency graphs with pnpm CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

// PackageManagerSupport returns discovery metadata for the internal pnpm CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerPNPM, "package.json").WithMultiModule()}
}

// Ready reports whether pnpm is available.
func (d NativeDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("pnpm")
	return detectorkit.CommandNotReadyError("pnpm", err)
}

// Applicable reports whether pnpm manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	for _, name := range []string{"package.json", "pnpm-lock.yaml"} {
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

// Descriptor describes the pnpm CLI fallback detector.
func (d NativeDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NamePNPMNative,
		RemediationCapabilities: pnpmNativeRemediationCapabilities(),
		Technique:               plugin.BuildToolTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerPNPM},
		Tags:                    []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a pnpm dependency graph via pnpm list.
func (d NativeDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pnpm", pnpmListArgs(req.ScopeFilter), "pnpm detector", node.DepGraphFromPNPMJSON)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachPnpmLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs:   model.SingleGraphContainer(depsGraph, detectorkit.InferManifestMetadata(req, pnpmManifestMetadataPatterns)),
		Warnings: node.PackageManagerWarnings(d.base().ProjectDir(req.ProjectPath), model.PackageManagerPNPM, node.LockfileFormat{}),
	}), nil
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

func pnpmListArgs(scope model.Scope) []string {
	args := []string{"list", "--json", "--depth", "Infinity"}
	switch scope {
	case model.ScopeRuntime:
		args = append(args, "--prod")
	case model.ScopeDevelopment:
		args = append(args, "--dev")
	}
	return args
}

// Install prepares pnpm dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	return d.base().Install(ctx, req, "pnpm", []string{"i"}, "pnpm detector")
}
