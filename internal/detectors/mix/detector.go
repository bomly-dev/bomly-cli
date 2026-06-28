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
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves Elixir Mix dependency graphs from committed Mix files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"mix.lock", "mix.exs"}

type mixPackage struct {
	Name    string
	Version string
	Source  string
	Scope   sdk.Scope
	Direct  bool
	Deps    []string
}

var (
	mixLockHexPattern  = regexp.MustCompile(`"([^"]+)"\s*:\s*\{:hex\s*,\s*:([A-Za-z0-9_.-]+)\s*,\s*"([^"]+)"`)
	mixDepPattern      = regexp.MustCompile(`\{(?:\s*:([A-Za-z0-9_.-]+)|\s*"([^"]+)")\s*,[^}\n]*(?:only:\s*(?::([A-Za-z0-9_]+)|\[([^]]+)]))?`)
	mixOnlyAtomPattern = regexp.MustCompile(`:([A-Za-z0-9_]+)`)
	// mixLockDepAtomPattern extracts a hex dep atom name from inside a dep tuple
	// like `{:cowlib, "~> 2.11.0", [hex: :cowlib, ...]}` — we only want :cowlib.
	mixLockDepAtomPattern = regexp.MustCompile(`\{\s*:([A-Za-z0-9_]+)`)
)

// PackageManagerSupport returns Mix package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerMix, evidencePatterns...)}
}

// Ready reports whether committed Mix files can be parsed.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether Mix files are present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
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
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameMix,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemElixir},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerMix},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves a Mix dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockRaw, err := readOptional(filepath.Join(workingDir, "mix.lock"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read mix.lock: %w", err)
	}
	manifestRaw, err := readOptional(filepath.Join(workingDir, "mix.exs"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read mix.exs: %w", err)
	}
	g, err := depGraphFromMix(lockRaw, manifestRaw)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachMixLockPositions(g, workingDir)
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

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return os.ReadFile(path)
}

func depGraphFromMix(lockRaw, manifestRaw []byte) (*sdk.Graph, error) {
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
		return nil, fmt.Errorf("mix files do not contain any dependencies")
	}

	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// Add all package nodes first.
	nodesByName := make(map[string]*sdk.Dependency, len(packages))
	for _, name := range sortedMixNames(packages) {
		pkg := packages[name]
		node := packageNode(pkg)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if pkg.Scope != "" {
			if existing, ok := g.Node(node.ID); ok {
				existing.AddScope(pkg.Scope)
			}
		}
		nodesByName[name] = node
	}

	// Wire root → direct deps only.
	for _, name := range sortedMixNames(packages) {
		pkg := packages[name]
		if !pkg.Direct {
			continue
		}
		node := nodesByName[name]
		if node == nil {
			continue
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add Mix root dependency %q: %w", node.ID, err)
		}
	}

	// Wire transitive edges from the dep list recorded in each lock entry.
	for _, name := range sortedMixNames(packages) {
		pkg := packages[name]
		parent := nodesByName[name]
		if parent == nil {
			continue
		}
		for _, depName := range pkg.Deps {
			child := nodesByName[depName]
			if child == nil || child.ID == root.ID || child.ID == parent.ID {
				continue
			}
			_ = g.AddEdge(parent.ID, child.ID)
		}
	}

	// Connect any orphan packages (no parents at all) directly to root.
	for _, node := range nodesByName {
		if node == nil {
			continue
		}
		dependents, _ := g.Dependents(node.ID)
		if len(dependents) == 0 {
			_ = g.AddEdge(root.ID, node.ID)
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
	// Any remaining unscoped non-root packages default to runtime.
	for _, pkg := range g.Nodes() {
		if pkg != nil && pkg.ID != root.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
	return g, nil
}

func parseMixLock(raw string) map[string]mixPackage {
	packages := make(map[string]mixPackage)
	for _, loc := range mixLockHexPattern.FindAllStringIndex(raw, -1) {
		match := mixLockHexPattern.FindStringSubmatch(raw[loc[0]:loc[1]])
		if match == nil {
			continue
		}
		lockName := strings.TrimSpace(match[1])
		name := strings.TrimSpace(match[2])
		if name == "" {
			name = lockName
		}
		// Extract the full line so we can parse the dep list at field index 5.
		lineEnd := strings.Index(raw[loc[0]:], "\n")
		var line string
		if lineEnd < 0 {
			line = raw[loc[0]:]
		} else {
			line = raw[loc[0] : loc[0]+lineEnd]
		}
		packages[name] = mixPackage{
			Name:    name,
			Version: strings.TrimSpace(match[3]),
			Source:  "hex",
			Deps:    extractMixLockDeps(line),
		}
	}
	return packages
}

// extractMixLockDeps extracts the dependency names from a single mix.lock line.
// Each line has the shape:
//
//	"name": {:hex, :atom, "version", "hash", [tools], [{:dep, ...}, ...], "repo", "cksum"}
//
// Field index 5 (0-based, separated by top-level commas) is the deps list.
// We extract it by tracking bracket/brace depth and counting top-level commas,
// then apply a simple regex to pull out dep atom names.
func extractMixLockDeps(line string) []string {
	// Find the opening '{' of the outer tuple.
	start := strings.Index(line, "{")
	if start < 0 {
		return nil
	}

	depth := 0
	commaCount := 0
	capturing := false
	var captured strings.Builder

	for i := start; i < len(line); i++ {
		ch := line[i]
		switch ch {
		case '{', '[':
			depth++
			if capturing {
				captured.WriteByte(ch)
			}
		case '}', ']':
			if capturing && depth == 1 {
				// Closing bracket ends the dep list field.
				capturing = false
			} else if capturing {
				captured.WriteByte(ch)
			}
			depth--
		case ',':
			if depth == 1 {
				commaCount++
				if commaCount == 5 {
					// Next content is field 5 — the deps list.
					capturing = true
				} else if commaCount > 5 && capturing {
					// Moved past field 5.
					capturing = false
				}
			} else if capturing {
				captured.WriteByte(ch)
			}
		default:
			if capturing {
				captured.WriteByte(ch)
			}
		}
	}

	field := captured.String()
	if field == "" {
		return nil
	}
	matches := mixLockDepAtomPattern.FindAllStringSubmatch(field, -1)
	if len(matches) == 0 {
		return nil
	}
	deps := make([]string, 0, len(matches))
	for _, m := range matches {
		if name := strings.TrimSpace(m[1]); name != "" {
			deps = append(deps, name)
		}
	}
	return deps
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
		scope := sdk.ScopeRuntime
		onlyValues := match[0] + " " + match[3] + " " + match[4]
		if strings.Contains(onlyValues, "test") || strings.Contains(onlyValues, "dev") {
			scope = sdk.ScopeDevelopment
		}
		for _, only := range mixOnlyAtomPattern.FindAllStringSubmatch(onlyValues, -1) {
			if only[1] == "prod" {
				scope = sdk.ScopeRuntime
			}
		}
		packages[name] = mixPackage{Name: name, Direct: true, Scope: scope}
	}
	return packages
}

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemElixir,
		Name:           "root",
		PackageManager: sdk.PackageManagerMix,
		Type:           sdk.PackageTypeApplication,
		Language:       "elixir"},
	})

}

func packageNode(pkg mixPackage) *sdk.Dependency {
	version := strings.TrimSpace(pkg.Version)
	source := strings.TrimSpace(pkg.Source)
	if source == "" {
		source = "hex"
	}
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemElixir,
		Name:           strings.TrimSpace(pkg.Name),
		Version:        version,
		PackageManager: sdk.PackageManagerMix,
		Type:           sdk.PackageTypePackage,
		Language:       "elixir",
		PURL:           sdk.BuildPackageURL("hex", "", pkg.Name, version)}, Metadata: map[string]any{
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

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := g.Node(node.ID); ok {
		return nil
	}
	if err := g.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
