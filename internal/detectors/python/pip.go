package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PipDetector resolves Python dependencies with pip inspect.
type PipDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var pipEvidencePatterns = []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"}

// PackageManagerSupport returns pip package-manager discovery metadata.
func (d PipDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPip, pipEvidencePatterns...)}
}

// Ready reports whether a Python interpreter is available.
func (d PipDetector) Ready() bool {
	_, err := pythonCommand()
	return err == nil
}

// Applicable reports whether pip-style manifests are present.
func (d PipDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock")
}

// Descriptor describes the pip detector.
func (d PipDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NamePip,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerPip},
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph with pip inspect.
func (d PipDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	command, err := pipInspectCommand()
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pip detector", command)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, d.base().workingDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PipDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d PipDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares pip dependencies before graph resolution.
func (d PipDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	requirementsFile, err := installRequirementsPath(d.base().workingDir(req.ProjectPath))
	if err != nil {
		return err
	}
	command, err := pythonCommand()
	if err != nil {
		return err
	}
	command = append(command, "-m", "pip", "install", "-r", requirementsFile)
	return d.base().install(ctx, req, "pip detector", command)
}
