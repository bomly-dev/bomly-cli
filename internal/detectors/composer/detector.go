package composer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type lockFile struct {
	Packages    []lockPackage `json:"packages"`
	PackagesDev []lockPackage `json:"packages-dev"`
}

type composerManifest struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type lockPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

// Detector resolves PHP Composer dependency graphs from composer.lock.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"composer.lock", "installed.json"}

// PackageManagerSupport returns Composer package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerComposer, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether a Composer lockfile is present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	return system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "composer.lock"))
}

// Descriptor describes the Composer detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameComposer,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPHP},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerComposer},
		Tags:                 []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Composer dependency graph from composer.lock.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	manifest, err := readComposerManifest(filepath.Join(workingDir, "composer.json"))
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	lockPath := filepath.Join(d.workingDir(req.ProjectPath), "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read composer lockfile: %w", err)
	}

	depsGraph, err := depGraphFromLock(data, manifest)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	AttachComposerLockPositions(depsGraph, workingDir)

	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

// Install prepares Composer dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	composerPath, err := system.LookPath("composer")
	if err != nil {
		return fmt.Errorf("resolve composer executable: %w", err)
	}

	args := append([]string{"install"}, req.InstallArgs...)
	cmd := system.Command(composerPath, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Info("Composer detector running install-first step")
	logger.Debug("running composer detector install-first", zap.String("working_dir", cmd.Dir), zap.String("executable", composerPath), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("composer detector install-first failure details", fields...)
		return fmt.Errorf("run composer install: %w", err)
	}
	logger.Info(fmt.Sprintf("Composer detector install-first completed in %s", logging.FormatDuration(time.Since(started))))
	return nil
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func depGraphFromLock(raw []byte, manifest composerManifest) (*sdk.Graph, error) {
	var lock lockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse composer lockfile: %w", err)
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPHP,
		Name:           "root",
		PackageManager: sdk.PackageManagerComposer,
		Type:           sdk.PackageTypeApplication,
		Language:       "php"},
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	packagesByName := make(map[string]lockPackage, len(lock.Packages)+len(lock.PackagesDev))
	for _, pkg := range append(append([]lockPackage{}, lock.Packages...), lock.PackagesDev...) {
		if strings.TrimSpace(pkg.Name) == "" {
			continue
		}
		packagesByName[pkg.Name] = pkg
		node := packageNode(pkg.Name, pkg.Version)
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	if len(packagesByName) == 0 {
		return nil, fmt.Errorf("composer lockfile does not contain any packages")
	}

	for _, pkg := range packagesByName {
		parent := packageNode(pkg.Name, pkg.Version)
		for dependency := range pkg.Require {
			childPkg, ok := packagesByName[dependency]
			if !ok {
				continue
			}
			child := packageNode(childPkg.Name, childPkg.Version)
			if err := addNodeIfMissing(depsGraph, child); err != nil {
				return nil, err
			}
			if err := depsGraph.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	runtimeRoots := resolveRootDependencies(manifest.Require, packagesByName, nil)
	developmentRoots := resolveRootDependencies(manifest.RequireDev, packagesByName, runtimeRoots)
	if len(runtimeRoots) == 0 && len(developmentRoots) == 0 {
		inferredRuntimeRoots, inferredDevelopmentRoots := inferRootDependencies(lock, packagesByName)
		runtimeRoots = inferredRuntimeRoots
		developmentRoots = inferredDevelopmentRoots
	}
	for _, name := range runtimeRoots {
		pkg := packagesByName[name]
		node := packageNode(pkg.Name, pkg.Version)
		if existing, ok := depsGraph.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeRuntime)
		}
		if err := depsGraph.AddEdge(rootNode.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add root runtime dependency %q: %w", node.ID, err)
		}
	}
	for _, name := range developmentRoots {
		pkg := packagesByName[name]
		node := packageNode(pkg.Name, pkg.Version)
		if existing, ok := depsGraph.Node(node.ID); ok {
			existing.AddScope(sdk.ScopeDevelopment)
		}
		if err := depsGraph.AddEdge(rootNode.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add root development dependency %q: %w", node.ID, err)
		}
	}

	propagateScope := func(startNames []string, scope sdk.Scope) error {
		visited := make(map[string]struct{}, len(packagesByName))
		var walk func(string) error
		walk = func(name string) error {
			if _, ok := visited[name]; ok {
				return nil
			}
			visited[name] = struct{}{}

			pkg, ok := packagesByName[name]
			if !ok {
				return nil
			}
			node := packageNode(pkg.Name, pkg.Version)
			if existing, ok := depsGraph.Node(node.ID); ok {
				existing.AddScope(scope)
			}
			for dependency := range pkg.Require {
				if err := walk(dependency); err != nil {
					return err
				}
			}
			return nil
		}
		for _, name := range startNames {
			if err := walk(name); err != nil {
				return err
			}
		}
		return nil
	}

	if err := propagateScope(developmentRoots, sdk.ScopeDevelopment); err != nil {
		return nil, err
	}
	if err := propagateScope(runtimeRoots, sdk.ScopeRuntime); err != nil {
		return nil, err
	}

	return depsGraph, nil
}

func packageNode(name, version string) *sdk.Dependency {
	org, packageName := splitPackageName(name)
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPHP,
		Org:            org,
		Name:           packageName,
		Version:        version,
		PURL:           sdk.BuildPackageURL("composer", org, packageName, version),
		PackageManager: sdk.PackageManagerComposer,
		Type:           sdk.PackageTypePackage,
		Language:       "php"},
	})

}

func splitPackageName(value string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), "/", 2)
	if len(parts) != 2 {
		return "", strings.TrimSpace(value)
	}
	return parts[0], parts[1]
}

func addNodeIfMissing(depsGraph *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := depsGraph.Node(node.ID); ok {
		return nil
	}
	if err := depsGraph.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}

func readComposerManifest(path string) (composerManifest, error) {
	exists, err := system.FileExists(path)
	if err != nil {
		return composerManifest{}, err
	}
	if !exists {
		return composerManifest{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return composerManifest{}, fmt.Errorf("read composer manifest: %w", err)
	}
	var manifest composerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return composerManifest{}, fmt.Errorf("parse composer manifest: %w", err)
	}
	return manifest, nil
}

func resolveRootDependencies(requirements map[string]string, packagesByName map[string]lockPackage, exclude []string) []string {
	if len(requirements) == 0 {
		return nil
	}
	excluded := make(map[string]struct{}, len(exclude))
	for _, name := range exclude {
		excluded[name] = struct{}{}
	}
	values := make([]string, 0, len(requirements))
	for name := range requirements {
		if _, ok := excluded[name]; ok {
			continue
		}
		if _, ok := packagesByName[name]; !ok {
			continue
		}
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}

func inferRootDependencies(lock lockFile, packagesByName map[string]lockPackage) ([]string, []string) {
	runtimeSet := make(map[string]struct{}, len(lock.Packages))
	for _, pkg := range lock.Packages {
		if pkg.Name == "" {
			continue
		}
		runtimeSet[pkg.Name] = struct{}{}
	}
	devSet := make(map[string]struct{}, len(lock.PackagesDev))
	for _, pkg := range lock.PackagesDev {
		if pkg.Name == "" {
			continue
		}
		devSet[pkg.Name] = struct{}{}
	}
	for _, pkg := range packagesByName {
		for dependency := range pkg.Require {
			delete(runtimeSet, dependency)
			delete(devSet, dependency)
		}
	}
	return setKeys(runtimeSet), setKeys(devSet)
}

func setKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
