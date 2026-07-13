package pnpm

import (
	"context"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NativeDetector resolves dependency graphs with pnpm CLI commands.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns discovery metadata for the internal pnpm CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPNPM, "package.json").WithNativeMultiModule()}
}

// Ready reports whether pnpm is available.
func (d NativeDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("pnpm")
	return detectors.CommandNotReadyError("pnpm", err)
}

// Applicable reports whether pnpm manifests are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
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
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		DiscoveryIgnoredDirectories: []string{"node_modules", "dist"},
		Name:                        detectors.NamePNPMNative,
		Technique:                   sdk.BuildToolTechnique,
		SupportedEcosystems:         []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:           []sdk.PackageManager{sdk.PackageManagerPNPM},
		Tags:                        []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:        true,
	}
}

// ResolveGraph resolves a pnpm dependency graph via pnpm list.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	depsGraph, err := d.base().ResolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pnpm", pnpmListArgs(req.ScopeFilter), "pnpm detector", node.DepGraphFromPNPMJSON)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPnpmLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pnpmManifestMetadataPatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}

func pnpmListArgs(scope sdk.Scope) []string {
	args := []string{"list", "--json", "--depth", "Infinity"}
	switch scope {
	case sdk.ScopeRuntime:
		args = append(args, "--prod")
	case sdk.ScopeDevelopment:
		args = append(args, "--dev")
	}
	return args
}

// Install prepares pnpm dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().Install(ctx, req, "pnpm", []string{"i"}, "pnpm detector")
}
