package bun

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

// NativeDetector resolves installed Bun dependencies with the Bun CLI.
// Bun exposes a hoisted installed-package tree, so nested edges are preserved,
// direct dependencies are recovered from package.json, and hoisted packages
// without a provable parent retain an unknown relationship.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns discovery metadata for the Bun CLI fallback detector.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerBun, bunEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether Bun is available.
func (d NativeDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("bun")
	return detectors.CommandNotReadyError("bun", err)
}

// Applicable reports whether a Bun project manifest is present.
func (d NativeDetector) Applicable(_ context.Context, req sdk.DetectionRequest) (bool, error) {
	return system.FileExists(filepath.Join(d.base().ProjectDir(req.ProjectPath), "package.json"))
}

// Descriptor describes the Bun CLI fallback detector.
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:   []string{"node_modules", "dist"},
		Name:                 detectors.NameBunNative,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerBun},
		Tags:                 []string{"installed-inventory", "component-targeting", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves the installed Bun package inventory via bun pm ls.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	manifest, err := node.ReadPackageJSONManifest(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Bun package manifest: %w", err)
	}
	graph, err := d.base().ResolveGraph(
		req.Stderr,
		req.ProjectPath,
		req.Verbose,
		"bun",
		[]string{"pm", "ls", "--all"},
		"Bun native detector",
		func(raw []byte) (*sdk.Graph, error) { return depGraphFromBunPMList(raw, manifest, workingDir, d.Logger) },
	)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(graph, detectors.InferManifestMetadata(req, []string{"package.json", "bun.lock", "bun.lockb"})),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() sdk.Detector { return d.Fallback }

// Install prepares Bun dependencies before graph resolution.
func (d NativeDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().Install(ctx, req, "bun", []string{"install"}, "Bun native detector")
}

func (d NativeDetector) base() node.BaseDetector {
	return node.BaseDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}
}
