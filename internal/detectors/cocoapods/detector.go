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
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Detector resolves CocoaPods dependency graphs from Podfile.lock.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
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
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerCocoaPods, evidencePatterns...)}
}

// Ready reports whether committed Podfile.lock files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Podfile.lock is present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	return system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), "Podfile.lock"))
}

// Descriptor describes the CocoaPods detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameCocoaPods,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSwift},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerCocoaPods},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing"},
	}
}

// ResolveGraph resolves a CocoaPods dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	raw, err := os.ReadFile(filepath.Join(workingDir, "Podfile.lock"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Podfile.lock: %w", err)
	}
	// Optionally parse the Podfile to identify pods that belong only to test
	// targets, so they can be annotated as development-scope.
	testPods := parsePodfileTestTargets(filepath.Join(workingDir, "Podfile"))
	g, err := depGraphFromLock(raw, testPods)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachPodfileLockPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns))}, nil
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

// depGraphFromLock builds a dependency graph from Podfile.lock.
// testPods is the set of pod root-names that appear ONLY in test targets in the
// Podfile; they are annotated as ScopeDevelopment. If nil, all pods are runtime.
func depGraphFromLock(raw []byte, testPods map[string]bool) (*sdk.Graph, error) {
	var lock podLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Podfile.lock: %w", err)
	}
	specs := parsePodSpecs(lock.Pods)
	if len(specs) == 0 {
		return nil, fmt.Errorf("podfile.lock does not contain any pods")
	}
	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
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
			if err := g.AddEdge(parent.ID, child.ID); err != nil {
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
		scope := sdk.ScopeRuntime
		if testPods[rootPodName(dep)] {
			scope = sdk.ScopeDevelopment
		}
		if existing, ok := g.Node(node.ID); ok {
			existing.AddScope(scope)
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add CocoaPods root dependency %q: %w", node.ID, err)
		}
	}
	// BFS scope propagation: runtime always beats development.
	directDeps, _ := g.DirectDependencies(root.ID)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.ID] = sdk.MergeScope(propagated[dep.ID], scope)
		dep.AddScope(propagated[dep.ID])
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == root.ID {
				continue
			}
			next := sdk.MergeScope(propagated[child.ID], scope)
			if next == propagated[child.ID] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.ID] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}
	// Any pods still without scope default to runtime.
	for _, pkg := range g.Nodes() {
		if pkg != nil && pkg.ID != root.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
	return g, nil
}

var podfileTargetHeadPattern = regexp.MustCompile(`(?i)target\s+'([^']+)'\s+do`)
var podfilePodNamePattern = regexp.MustCompile(`(?i)^\s*pod\s+'([^']+)'`)

// parsePodfileTestTargets parses the Podfile and returns the root pod names that
// appear ONLY inside test target blocks (blocks whose name contains "test" or "spec").
// Pods that appear in both test and non-test targets are treated as runtime.
// Returns nil if the Podfile cannot be read.
func parsePodfileTestTargets(path string) map[string]bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	type frame struct{ isTest bool }
	stack := []frame{}
	mainPods := make(map[string]bool)
	testPods := make(map[string]bool)

	isTestName := func(name string) bool {
		lower := strings.ToLower(name)
		return strings.Contains(lower, "test") || strings.Contains(lower, "spec")
	}

	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if m := podfileTargetHeadPattern.FindStringSubmatch(line); m != nil {
			parentIsTest := len(stack) > 0 && stack[len(stack)-1].isTest
			stack = append(stack, frame{isTest: parentIsTest || isTestName(m[1])})
			continue
		}
		if trimmed == "end" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if m := podfilePodNamePattern.FindStringSubmatch(line); m != nil {
			podName := rootPodName(m[1])
			if len(stack) > 0 && stack[len(stack)-1].isTest {
				testPods[podName] = true
			} else {
				mainPods[podName] = true
			}
		}
	}

	result := make(map[string]bool)
	for name := range testPods {
		if !mainPods[name] {
			result[name] = true
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
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

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{
		Ecosystem:   string(sdk.EcosystemSwift),
		Name:        "root",
		BuildSystem: sdk.PackageManagerCocoaPods.Name(),
		Type:        "application",
		Language:    "swift",
	})

}

func packageNode(name, version, checksum string) *sdk.Dependency { //nolint:unparam
	node := sdk.NewDependency(sdk.Dependency{
		Ecosystem:   string(sdk.EcosystemSwift),
		Name:        name,
		Version:     strings.TrimSpace(version),
		BuildSystem: sdk.PackageManagerCocoaPods.Name(),
		Type:        "pod",
		Language:    "swift",
		PURL:        sdk.BuildPackageURL("cocoapods", "", name, version),
	})

	if strings.TrimSpace(checksum) != "" {
		node.Digests = append(node.Digests, sdk.Digest{Algorithm: "podspec-checksum", Value: strings.TrimSpace(checksum)})
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

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := g.Node(node.ID); ok {
		return nil
	}
	if err := g.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
