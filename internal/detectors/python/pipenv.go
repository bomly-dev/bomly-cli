package python

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PipenvDetector resolves Python dependencies through Pipenv.
type PipenvDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var pipenvEvidencePatterns = []string{"Pipfile", "Pipfile.lock"}

// PackageManagerSupport returns Pipenv package-manager discovery metadata.
func (d PipenvDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPipenv, pipenvEvidencePatterns...)}
}

// Ready reports whether Pipenv is available.
func (d PipenvDetector) Ready() bool {
	_, err := system.LookPath("pipenv")
	return err == nil
}

// Applicable reports whether Pipenv manifests are present.
func (d PipenvDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "Pipfile", "Pipfile.lock")
}

// Descriptor describes the Pipenv detector.
func (d PipenvDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NamePipenv,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerPipenv},
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through Pipenv.
func (d PipenvDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	if depsGraph, err := depGraphFromPipfileLock(filepath.Join(d.base().workingDir(req.ProjectPath), "Pipfile.lock")); err == nil {
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipenvEvidencePatterns)),
		}, nil
	}
	command, err := pipInspectCommand("pipenv", "run")
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Pipenv detector", command)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipenvEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PipenvDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d PipenvDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Pipenv dependencies before graph resolution.
func (d PipenvDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	if exists, err := system.FileExists(filepath.Join(d.base().workingDir(req.ProjectPath), "Pipfile.lock")); err != nil {
		return err
	} else if exists {
		return nil
	}
	return d.base().install(ctx, req, "Pipenv detector", []string{"pipenv", "install"})
}

type pipfileLock struct {
	Default map[string]pipfileLockPackage `json:"default"`
	Develop map[string]pipfileLockPackage `json:"develop"`
}

type pipfileLockPackage struct {
	Version string `json:"version"`
}

func depGraphFromPipfileLock(path string) (*sdk.Graph, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}
	var lock pipfileLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	if len(lock.Default) == 0 && len(lock.Develop) == 0 {
		return nil, fmt.Errorf("pipfile.lock does not contain dependencies")
	}
	depsGraph := sdk.New()
	root := sdk.NewPackage(sdk.Package{
		Ecosystem:   string(sdk.EcosystemPython),
		BuildSystem: sdk.PackageManagerPipenv.Name(),
		Name:        "root",
		Type:        "project",
	})
	if err := depsGraph.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root package: %w", err)
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Default, sdk.ScopeRuntime); err != nil {
		return nil, err
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Develop, sdk.ScopeDevelopment); err != nil {
		return nil, err
	}
	return depsGraph, nil
}

func addPipfileLockPackages(depsGraph *sdk.Graph, root *sdk.Package, packages map[string]pipfileLockPackage, scope sdk.Scope) error {
	for name, pkg := range packages {
		normalizedName := normalizePythonName(name)
		node := sdk.NewPackage(sdk.Package{
			Ecosystem:   string(sdk.EcosystemPython),
			BuildSystem: sdk.PackageManagerPipenv.Name(),
			Name:        normalizedName,
			Version:     strings.TrimPrefix(pkg.Version, "=="),
			Scope:       string(scope),
		})
		if _, exists := depsGraph.Package(node.ID); !exists {
			if err := depsGraph.AddPackage(node); err != nil {
				return fmt.Errorf("add Pipfile.lock package %q: %w", normalizedName, err)
			}
		}
		if err := depsGraph.AddDependency(root.ID, node.ID); err != nil {
			return fmt.Errorf("add Pipfile.lock dependency %q: %w", normalizedName, err)
		}
	}
	return nil
}
