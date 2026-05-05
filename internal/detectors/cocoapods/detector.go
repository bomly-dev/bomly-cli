package cocoapods

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
	"gopkg.in/yaml.v3"
)

// Detector resolves CocoaPods dependency graphs from Podfile.lock.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var evidencePatterns = []string{"Podfile.lock", "Podfile"}

type podLock struct {
	Pods         []any             `yaml:"PODS"`
	Dependencies []string          `yaml:"DEPENDENCIES"`
	Checksums    map[string]string `yaml:"SPEC CHECKSUMS"`
}

type podSpec struct {
	Name         string
	Version      string
	Dependencies []string
}

var podLinePattern = regexp.MustCompile(`^\s*([^()\s][^()]*)\s*(?:\(([^()]*)\))?\s*$`)

// PackageManagerSupport returns CocoaPods package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerCocoaPods, evidencePatterns...)}
}

// Ready reports whether committed Podfile.lock files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Podfile.lock is present.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	return system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Podfile.lock"))
}

// Descriptor describes the CocoaPods detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameCocoaPods,
		Enabled:             true,
		Origin:              model.CoreOrigin,
		Technique:           model.LockfileTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemSwift},
		SupportedManagers:   []model.PackageManager{model.PackageManagerCocoaPods},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "lockfile-parsing"},
	}
}

// ResolveGraph resolves a CocoaPods dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	path := filepath.Join(d.workingDir(req.ProjectPath), "Podfile.lock")
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("read Podfile.lock: %w", err)
	}
	g, err := depGraphFromLock(raw)
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

func depGraphFromLock(raw []byte) (*model.Graph, error) {
	var lock podLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Podfile.lock: %w", err)
	}
	specs := parsePodSpecs(lock.Pods)
	if len(specs) == 0 {
		return nil, fmt.Errorf("Podfile.lock does not contain any pods")
	}
	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedPodNames(specs) {
		spec := specs[name]
		node := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedPodNames(specs) {
		spec := specs[name]
		parent := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		for _, depRef := range spec.Dependencies {
			depName, _ := parsePodRef(depRef)
			childSpec, ok := findPodSpec(specs, depName)
			if !ok {
				continue
			}
			child := packageNode(childSpec.Name, childSpec.Version, lock.Checksums[rootPodName(childSpec.Name)])
			if err := g.AddDependency(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add CocoaPods dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}
	for _, dep := range rootDependencies(lock.Dependencies) {
		spec, ok := findPodSpec(specs, dep)
		if !ok {
			continue
		}
		node := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		if existing, ok := g.Package(node.ID); ok {
			model.MergePackageScope(existing, model.ScopeRuntime)
		}
		if err := g.AddDependency(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add CocoaPods root dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func parsePodSpecs(items []any) map[string]podSpec {
	specs := make(map[string]podSpec)
	for _, item := range items {
		switch value := item.(type) {
		case string:
			name, version := parsePodRef(value)
			if name != "" {
				specs[name] = podSpec{Name: name, Version: version}
			}
		case map[string]any:
			for rawName, rawDeps := range value {
				name, version := parsePodRef(rawName)
				if name == "" {
					continue
				}
				spec := podSpec{Name: name, Version: version}
				if deps, ok := rawDeps.([]any); ok {
					for _, dep := range deps {
						if depText, ok := dep.(string); ok {
							spec.Dependencies = append(spec.Dependencies, depText)
						}
					}
				}
				specs[name] = spec
			}
		}
	}
	return specs
}

func parsePodRef(value string) (string, string) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "- ")
	matches := podLinePattern.FindStringSubmatch(value)
	if len(matches) == 0 {
		return rootPodName(value), ""
	}
	return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2])
}

func rootDependencies(values []string) []string {
	roots := make([]string, 0, len(values))
	for _, value := range values {
		name, _ := parsePodRef(value)
		if name != "" {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)
	return roots
}

func rootNode() *model.Package {
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemSwift),
		Name:        "root",
		BuildSystem: model.PackageManagerCocoaPods.Name(),
		Type:        "application",
		Language:    "swift",
	})
}

func packageNode(name, version, checksum string) *model.Package {
	node := model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemSwift),
		Name:        name,
		Version:     strings.TrimSpace(version),
		BuildSystem: model.PackageManagerCocoaPods.Name(),
		Type:        "pod",
		Language:    "swift",
		PURL:        model.BuildPackageURL("cocoapods", "", name, version),
	})
	if strings.TrimSpace(checksum) != "" {
		node.Digests = append(node.Digests, model.Digest{Algorithm: "podspec-checksum", Value: strings.TrimSpace(checksum)})
	}
	return node
}

func findPodSpec(specs map[string]podSpec, name string) (podSpec, bool) {
	if spec, ok := specs[name]; ok {
		return spec, true
	}
	root := rootPodName(name)
	for candidate, spec := range specs {
		if rootPodName(candidate) == root {
			return spec, true
		}
	}
	return podSpec{}, false
}

func rootPodName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.Index(name, "/"); i >= 0 {
		return name[:i]
	}
	return name
}

func sortedPodNames(specs map[string]podSpec) []string {
	values := make([]string, 0, len(specs))
	for name := range specs {
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
