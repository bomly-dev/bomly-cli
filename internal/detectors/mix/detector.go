package mix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves Elixir Mix dependency graphs from committed Mix files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var evidencePatterns = []string{"mix.lock", "mix.exs"}

type mixPackage struct {
	Name    string
	Version string
	Source  string
	Scope   model.Scope
	Direct  bool
}

var (
	mixLockHexPattern  = regexp.MustCompile(`"([^"]+)"\s*:\s*\{:(?:hex)\s*,\s*:([A-Za-z0-9_.-]+)\s*,\s*"([^"]+)"`)
	mixDepPattern      = regexp.MustCompile(`\{(?:\s*:([A-Za-z0-9_.-]+)|\s*"([^"]+)")\s*,[^}\n]*(?:only:\s*(?::([A-Za-z0-9_]+)|\[([^\]]+)\]))?`)
	mixOnlyAtomPattern = regexp.MustCompile(`:([A-Za-z0-9_]+)`)
)

// PackageManagerSupport returns Mix package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerMix, evidencePatterns...)}
}

// Ready reports whether committed Mix files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Mix files are present.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range []string{"mix.lock", "mix.exs"} {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// Descriptor describes the Mix detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameMix,
		Enabled:             true,
		ComponentType:       model.NativeComponent,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemElixir},
		SupportedManagers:   []model.PackageManager{model.PackageManagerMix},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a Mix dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockRaw, err := readOptional(filepath.Join(workingDir, "mix.lock"))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("read mix.lock: %w", err)
	}
	manifestRaw, err := readOptional(filepath.Join(workingDir, "mix.exs"))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("read mix.exs: %w", err)
	}
	g, err := depGraphFromMix(lockRaw, manifestRaw)
	if err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{Graphs: model.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns))}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return os.ReadFile(path)
}

func depGraphFromMix(lockRaw, manifestRaw []byte) (*model.Graph, error) {
	packages := parseMixLock(string(lockRaw))
	for name, dep := range parseMixManifest(string(manifestRaw)) {
		pkg := packages[name]
		if pkg.Name == "" {
			pkg.Name = name
		}
		pkg.Direct = true
		pkg.Scope = dep.Scope
		packages[name] = pkg
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("Mix files do not contain any dependencies")
	}

	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedMixNames(packages) {
		pkg := packages[name]
		node := packageNode(pkg)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if pkg.Scope != "" {
			if existing, ok := g.Package(node.ID); ok {
				model.MergePackageScope(existing, pkg.Scope)
			}
		}
		if pkg.Direct {
			if err := g.AddDependency(root.ID, node.ID); err != nil {
				return nil, fmt.Errorf("add Mix root dependency %q: %w", node.ID, err)
			}
		}
	}
	return g, nil
}

func parseMixLock(raw string) map[string]mixPackage {
	packages := make(map[string]mixPackage)
	for _, match := range mixLockHexPattern.FindAllStringSubmatch(raw, -1) {
		lockName := strings.TrimSpace(match[1])
		name := strings.TrimSpace(match[2])
		if name == "" {
			name = lockName
		}
		packages[name] = mixPackage{
			Name:    name,
			Version: strings.TrimSpace(match[3]),
			Source:  "hex",
		}
	}
	return packages
}

func parseMixManifest(raw string) map[string]mixPackage {
	packages := make(map[string]mixPackage)
	for _, match := range mixDepPattern.FindAllStringSubmatch(raw, -1) {
		name := strings.TrimSpace(match[1])
		if name == "" {
			name = strings.TrimSpace(match[2])
		}
		if name == "" {
			continue
		}
		scope := model.ScopeRuntime
		onlyValues := match[0] + " " + match[3] + " " + match[4]
		if strings.Contains(onlyValues, "test") || strings.Contains(onlyValues, "dev") {
			scope = model.ScopeDevelopment
		}
		for _, only := range mixOnlyAtomPattern.FindAllStringSubmatch(onlyValues, -1) {
			if only[1] == "prod" {
				scope = model.ScopeRuntime
			}
		}
		packages[name] = mixPackage{Name: name, Direct: true, Scope: scope}
	}
	return packages
}

func rootNode() *model.Package {
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemElixir),
		Name:        "root",
		BuildSystem: model.PackageManagerMix.Name(),
		Type:        "application",
		Language:    "elixir",
	})
}

func packageNode(pkg mixPackage) *model.Package {
	version := strings.TrimSpace(pkg.Version)
	source := strings.TrimSpace(pkg.Source)
	if source == "" {
		source = "hex"
	}
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemElixir),
		Name:        strings.TrimSpace(pkg.Name),
		Version:     version,
		BuildSystem: model.PackageManagerMix.Name(),
		Type:        "package",
		Language:    "elixir",
		PURL:        model.BuildPackageURL("hex", "", pkg.Name, version),
		Metadata: map[string]any{
			"source": source,
		},
	})
}

func sortedMixNames(packages map[string]mixPackage) []string {
	values := make([]string, 0, len(packages))
	for name := range packages {
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}

func addNodeIfMissing(g *model.Graph, node *model.Package) error {
	if _, ok := g.Package(node.ID); ok {
		return nil
	}
	if err := g.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
