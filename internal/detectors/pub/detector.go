package pub

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	sdk "github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Detector resolves Dart pub dependency graphs from pubspec files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"pubspec.lock", "pubspec.yaml", "pubspec.yml"}

type pubLock struct {
	Packages map[string]pubLockPackage `yaml:"packages"`
}

type pubLockPackage struct {
	Dependency  string `yaml:"dependency"`
	Description any    `yaml:"description"`
	Source      string `yaml:"source"`
	Version     string `yaml:"version"`
}

type pubspec struct {
	Name            string         `yaml:"name"`
	Version         string         `yaml:"version"`
	Dependencies    map[string]any `yaml:"dependencies"`
	DevDependencies map[string]any `yaml:"dev_dependencies"`
}

// PackageManagerSupport returns pub package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPub, evidencePatterns...)}
}

// Ready reports whether committed pub lockfiles can be parsed.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether pub manifests are present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range []string{"pubspec.lock", "pubspec.yaml", "pubspec.yml"} {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// Descriptor describes the pub detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NamePub,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemDart},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerPub},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a pub dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	lockPath := filepath.Join(workingDir, "pubspec.lock")
	lockRaw, err := system.ReadRepositoryFile(lockPath)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read pub lockfile: %w", err)
	}
	manifest, err := readPubspec(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	g, err := depGraphFromLock(lockRaw, manifest)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPubspecLockPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns))}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func readPubspec(workingDir string) (pubspec, error) {
	for _, name := range []string{"pubspec.yaml", "pubspec.yml"} {
		path := filepath.Join(workingDir, name)
		ok, err := system.FileExists(path)
		if err != nil {
			return pubspec{}, err
		}
		if !ok {
			continue
		}
		raw, err := system.ReadRepositoryFile(path)
		if err != nil {
			return pubspec{}, fmt.Errorf("read pubspec: %w", err)
		}
		var spec pubspec
		if err := yaml.Unmarshal(raw, &spec); err != nil {
			return pubspec{}, fmt.Errorf("parse pubspec: %w", err)
		}
		return spec, nil
	}
	return pubspec{}, nil
}

func depGraphFromLock(raw []byte, manifest pubspec) (*sdk.Graph, error) {
	var lock pubLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse pub lockfile: %w", err)
	}
	if len(lock.Packages) == 0 {
		return nil, fmt.Errorf("pub lockfile does not contain any packages")
	}
	g := sdk.New()
	root, err := rootNode(manifest)
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedPackageNames(lock.Packages) {
		pkg := lock.Packages[name]
		node, err := packageNode(name, pkg)
		if err != nil {
			return nil, err
		}
		scope := scopeForPackage(name, pkg, manifest)
		if scope != "" {
			node.AddScope(scope)
		}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add pub dependency %q: %w", node.NodeID(), err)
		}
	}
	return g, nil
}

func rootNode(manifest pubspec) (*sdk.ModuleNode, error) {
	name := strings.TrimSpace(manifest.Name)
	if name == "" {
		name = "root"
	}
	return sdk.NewModuleNode("pubspec.yaml", sdk.Coordinates{Ecosystem: sdk.EcosystemDart,
		Name:           name,
		Version:        strings.TrimSpace(manifest.Version),
		PackageManager: sdk.PackageManagerPub,
		Type:           sdk.PackageTypeApplication,
		Language:       "dart"})

}

func packageNode(name string, pkg pubLockPackage) (*sdk.DependencyNode, error) {
	metadata := map[string]any{
		"source": strings.TrimSpace(pkg.Source),
	}
	if revision := descriptionString(pkg.Description, "resolved-ref"); revision != "" {
		metadata["source_revision"] = revision
	}
	node, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: sdk.EcosystemDart,
		Name:           name,
		Version:        strings.TrimSpace(pkg.Version),
		PackageManager: sdk.PackageManagerPub,
		Type:           sdk.PackageTypePackage,
		Language:       "dart",
		PURL:           sdk.BuildPackageURL("pub", "", name, pkg.Version)})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}
	node.Source = pubDependencySource(pkg.Source)
	node.Metadata = metadata

	if resolved := resolvedURL(pkg.Description); resolved != "" {
		node.ResolvedURL = resolved
	}
	if pubDependencySource(pkg.Source) == sdk.DependencySourceGit {
		// A git package names its repository and the commit pub resolved.
		// A hosted package's "url" is the pub server, and path is local.
		if origin := sdk.RepositoryOrigin(descriptionString(pkg.Description, "url"), descriptionString(pkg.Description, "resolved-ref")); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}
	return node, nil
}

func pubDependencySource(source string) sdk.DependencySource {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "hosted":
		return sdk.DependencySourceRegistry
	case "git":
		return sdk.DependencySourceGit
	case "path":
		return sdk.DependencySourceFile
	default:
		return ""
	}
}

func scopeForPackage(name string, pkg pubLockPackage, manifest pubspec) sdk.Scope {
	if _, ok := manifest.DevDependencies[name]; ok {
		return sdk.ScopeDevelopment
	}
	if _, ok := manifest.Dependencies[name]; ok {
		return sdk.ScopeRuntime
	}
	switch strings.TrimSpace(pkg.Dependency) {
	case "direct dev":
		return sdk.ScopeDevelopment
	case "direct main":
		return sdk.ScopeRuntime
	default:
		return sdk.ScopeRuntime
	}
}

func resolvedURL(description any) string {
	for _, key := range []string{"url", "path"} {
		if value := descriptionString(description, key); value != "" {
			return value
		}
	}
	return ""
}

func descriptionString(description any, key string) string {
	m, ok := description.(map[string]any)
	if !ok {
		return ""
	}
	if value, ok := m[key].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return ""
}

func sortedPackageNames(packages map[string]pubLockPackage) []string {
	values := make([]string, 0, len(packages))
	for name := range packages {
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}

func addNodeIfMissing(g *sdk.Graph, node *sdk.DependencyNode) error {
	_, err := detectorkit.EnsureNode(g, node)
	return err
}
