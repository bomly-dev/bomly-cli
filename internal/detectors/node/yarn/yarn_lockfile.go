package yarn

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
)

// LockfileDetector resolves dependency graphs with Yarn.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

var yarnEvidencePatterns = []string{"yarn.lock"}
var yarnManifestMetadataPatterns = []string{"yarn.lock", "package.json"}

// PackageManagerSupport returns Yarn package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerYarn, yarnEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether Yarn is available.
func (d LockfileDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether a Yarn lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	exists, err := system.FileExists(filepath.Join(workingDir, "yarn.lock"))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Descriptor describes the Yarn detector.
func (d LockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameYarnLockfile,
		RemediationCapabilities: yarnLockfileRemediationCapabilities(),
		Technique:               sdk.LockfileTechnique,
		SupportedEcosystems:     []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:       []sdk.PackageManager{sdk.PackageManagerYarn},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Yarn dependency graph from yarn.lock.
func (d LockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	depsGraph, err := depGraphFromYarnLockfile(d.base().ProjectDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("yarn lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponentsToApplication(depsGraph, d.Logger, detectors.NameYarnLockfile, "yarn.lock"); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("yarn lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(d.base().ProjectDir(req.ProjectPath), depsGraph); err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachYarnLockPositions(depsGraph, d.base().ProjectDir(req.ProjectPath))

	workingDir := d.base().ProjectDir(req.ProjectPath)
	manifest := detectorkit.InferManifestMetadata(req, yarnManifestMetadataPatterns)
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, manifest),
		Warnings: node.PackageManagerWarnings(workingDir, sdk.PackageManagerYarn,
			node.LockfileFormat{File: "yarn.lock", Version: yarnLockfileFormat(workingDir)}),
	}, nil
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}
