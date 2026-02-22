package syft

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// Detector resolves dependency graphs through the Syft Go library (builtin)
// or the syft CLI binary (external).
type Detector struct {
	Logger              *zap.Logger
	WorkingDir          string
	SupportedEcosystems []detectors.Ecosystem
	SupportedManagers   []detectors.PackageManager
}

// Ready reports whether the detector is ready to run.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Syft should run for the requested project.
func (d Detector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx

	if req.ExecutionTarget.Kind == detectors.ExecutionTargetContainerImage {
		return true, nil
	}

	workingDir := syftWorkingDir(d.WorkingDir, req)

	if isSingleFileTarget(workingDir) {
		return true, nil
	}

	for _, candidate := range supportedFilesForManager(req.PackageManager) {
		exists, err := syftPatternExists(workingDir, candidate)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the Syft-backed detector.
func (d Detector) Descriptor() detectors.DetectorDescriptor {
	supportedEcosystems := d.SupportedEcosystems
	if len(supportedEcosystems) == 0 {
		supportedEcosystems = detectors.PreferredEcosystemsForDetector("syft-detector")
	}
	supportedManagers := d.SupportedManagers
	if len(supportedManagers) == 0 {
		supportedManagers = detectors.PreferredPackageManagersForDetector("syft-detector")
	}
	return detectors.DetectorDescriptor{
		Name:                "syft-detector",
		ImplementationType:  detectors.ThirdPartyDetector,
		SupportedEcosystems: supportedEcosystems,
		SupportedManagers:   supportedManagers,
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "sbom-import", "detector-enrichment"},
	}
}

func supportedFilesForManager(manager detectors.PackageManager) []string {
	return detectors.EvidencePatternsForPackageManager(manager)
}

func syftPatternExists(dir string, pattern string) (bool, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		exists, err := system.FileExists(filepath.Join(dir, filepath.FromSlash(pattern)))
		return err == nil && exists, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	if err != nil {
		return false, err
	}
	return len(matches) > 0, nil
}

func syftWorkingDir(defaultWorkingDir string, req detectors.ResolveGraphRequest) string {
	if defaultWorkingDir != "" {
		return defaultWorkingDir
	}
	if req.ProjectPath != "" {
		return req.ProjectPath
	}
	return req.ExecutionTarget.Location
}

func isSingleFileTarget(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
