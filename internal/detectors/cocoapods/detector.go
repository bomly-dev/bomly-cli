package cocoapods

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	sdk "github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
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
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
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
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSwift},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerCocoaPods},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing"},
	}
}

// ResolveGraph resolves a CocoaPods dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	raw, err := system.ReadRepositoryFile(filepath.Join(workingDir, "Podfile.lock"))
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
	root, err := rootNode()
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedPodNames(specs) {
		spec := specs[name]
		node, err := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		if err != nil {
			return nil, err
		}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedPodNames(specs) {
		spec := specs[name]
		parent, err := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		if err != nil {
			return nil, err
		}
		for _, depRef := range spec.Dependencies {
			depName, _ := parsePodRef(depRef)
			childSpec, ok := findPodSpec(specs, depName)
			if !ok {
				continue
			}
			child, err := packageNode(childSpec.Name, childSpec.Version, lock.Checksums[rootPodName(childSpec.Name)])
			if err != nil {
				return nil, err
			}
			if err := g.AddEdge(parent.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add CocoaPods dependency %q -> %q: %w", parent.NodeID(), child.NodeID(), err)
			}
		}
	}
	for _, dep := range rootDependencies(lock.Dependencies) {
		spec, ok := findPodSpec(specs, dep)
		if !ok {
			continue
		}
		node, err := packageNode(spec.Name, spec.Version, lock.Checksums[rootPodName(spec.Name)])
		if err != nil {
			return nil, err
		}
		scope := sdk.ScopeRuntime
		if testPods[rootPodName(dep)] {
			scope = sdk.ScopeDevelopment
		}
		if existingNode, ok := g.Node(node.NodeID()); ok {
			if existing, isDep := sdk.AsDependencyNode(existingNode); isDep {
				existing.AddScope(scope)
			}
		}
		if err := g.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add CocoaPods root dependency %q: %w", node.NodeID(), err)
		}
	}
	// BFS scope propagation: runtime always beats development.
	directDepNodes, _ := g.DirectDependencies(root.NodeID())
	directDeps := sdk.DependencyNodesOf(directDepNodes)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.DependencyNode, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := dep.PrimaryScope()
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.NodeID()] = sdk.MergeScope(propagated[dep.NodeID()], scope)
		dep.AddScope(propagated[dep.NodeID()])
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.NodeID()]
		if scope == sdk.ScopeUnknown {
			continue
		}
		childNodes, err := g.DirectDependencies(current.NodeID())
		if err != nil {
			continue
		}
		children := sdk.DependencyNodesOf(childNodes)
		for _, child := range children {
			if child == nil || child.NodeID() == root.NodeID() {
				continue
			}
			next := sdk.MergeScope(propagated[child.NodeID()], scope)
			if next == propagated[child.NodeID()] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.NodeID()] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}
	// Any pods still without scope default to runtime.
	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && pkg.NodeID() != root.NodeID() && pkg.PrimaryScope() == sdk.ScopeUnknown {
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
	raw, err := system.ReadRepositoryFile(path)
	if err != nil {
		return nil
	}

	type frame struct{ isTest bool }
	var stack []frame
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

// rootNode is the scanned project's own artifact, so it is a module node:
// ADR-0041 made ownership the node kind rather than a FirstParty flag.
func rootNode() (*sdk.ModuleNode, error) {
	return sdk.NewModuleNode("Podfile", sdk.Coordinates{
		Ecosystem:      sdk.EcosystemSwift,
		Name:           "root",
		PackageManager: sdk.PackageManagerCocoaPods,
		Type:           sdk.PackageTypeApplication,
		Language:       "swift",
	})
}

func packageNode(name, version, checksum string) (*sdk.DependencyNode, error) {
	node, err := sdk.NewDependencyNode(sdk.Coordinates{
		Ecosystem:      sdk.EcosystemSwift,
		Name:           name,
		Version:        strings.TrimSpace(version),
		PackageManager: sdk.PackageManagerCocoaPods,
		Type:           "pod",
		Language:       "swift",
		PURL:           sdk.BuildPackageURL("cocoapods", "", name, version),
	})
	if err != nil {
		return nil, fmt.Errorf("build pod node %q: %w", name, err)
	}
	if strings.TrimSpace(checksum) != "" {
		node.Digests = append(node.Digests, sdk.Digest{Algorithm: "podspec-checksum", Value: strings.TrimSpace(checksum)})
	}
	return node, nil
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

func addNodeIfMissing(g *sdk.Graph, node *sdk.DependencyNode) error {
	_, err := detectorkit.EnsureNode(g, node)
	return err
}
