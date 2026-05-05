package swiftpm

import (
	"context"
	"encoding/json"
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

// Detector resolves Swift Package Manager dependency graphs from Package.resolved.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var evidencePatterns = []string{"Package.resolved", ".package.resolved", "Package.swift", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"}

type packageResolved struct {
	Object struct {
		Pins []resolvedPin `json:"pins"`
	} `json:"object"`
	Pins []resolvedPin `json:"pins"`
}

type resolvedPin struct {
	Identity    string        `json:"identity"`
	Package     string        `json:"package"`
	Repository  string        `json:"repositoryURL"`
	Location    string        `json:"location"`
	State       resolvedState `json:"state"`
	Description struct {
		Identity string `json:"identity"`
	} `json:"description"`
}

type resolvedState struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Branch   string `json:"branch"`
}

type swiftPackage struct {
	Name        string
	Version     string
	Repository  string
	Revision    string
	Requirement string
	Direct      bool
}

var packageSwiftPattern = regexp.MustCompile(`\.package\s*\([^)]*(?:url:\s*"([^"]+)"|name:\s*"([^"]+)")[^)]*(?:from:|exact:|branch:|revision:)\s*"([^"]+)"`)

// PackageManagerSupport returns SwiftPM package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerSwiftPM, evidencePatterns...)}
}

// Ready reports whether committed SwiftPM files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether SwiftPM files are present.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range evidencePatterns {
		if ok, err := system.FileExists(filepath.Join(workingDir, name)); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// Descriptor describes the SwiftPM detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameSwiftPM,
		Enabled:             true,
		Origin:              model.CoreOrigin,
		Technique:           model.LockfileTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemSwift},
		SupportedManagers:   []model.PackageManager{model.PackageManagerSwiftPM},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "lockfile-parsing"},
	}
}

// ResolveGraph resolves a SwiftPM dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	resolvedRaw, resolvedPath, err := readFirstExisting(workingDir, []string{"Package.resolved", ".package.resolved", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"})
	if err != nil {
		return model.DetectionResult{}, err
	}
	manifestRaw, err := readOptional(filepath.Join(workingDir, "Package.swift"))
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("read Package.swift: %w", err)
	}
	g, err := depGraphFromSwiftPM(resolvedRaw, manifestRaw)
	if err != nil {
		return model.DetectionResult{}, err
	}
	metadataPatterns := evidencePatterns
	if resolvedPath != "" {
		metadataPatterns = append([]string{filepath.Base(resolvedPath)}, evidencePatterns...)
	}
	return model.DetectionResult{Graphs: model.SingleGraphContainer(g, detectors.InferManifestMetadata(req, metadataPatterns))}, nil
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

func depGraphFromSwiftPM(resolvedRaw, manifestRaw []byte) (*model.Graph, error) {
	packages, err := parseResolved(resolvedRaw)
	if err != nil {
		return nil, err
	}
	for name, direct := range parsePackageSwift(string(manifestRaw)) {
		pkg := packages[name]
		if pkg.Name == "" {
			pkg.Name = name
		}
		pkg.Direct = true
		if direct.Requirement != "" {
			pkg.Requirement = direct.Requirement
		}
		if direct.Repository != "" {
			pkg.Repository = direct.Repository
		}
		packages[name] = pkg
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("SwiftPM files do not contain any dependencies")
	}
	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedNames(packages) {
		pkg := packages[name]
		node := packageNode(pkg)
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if pkg.Direct || len(manifestRaw) == 0 {
			if err := g.AddDependency(root.ID, node.ID); err != nil {
				return nil, fmt.Errorf("add SwiftPM root dependency %q: %w", node.ID, err)
			}
		}
	}
	return g, nil
}

func parseResolved(raw []byte) (map[string]swiftPackage, error) {
	packages := make(map[string]swiftPackage)
	if len(raw) == 0 {
		return packages, nil
	}
	var resolved packageResolved
	if err := json.Unmarshal(raw, &resolved); err != nil {
		return nil, fmt.Errorf("parse Package.resolved: %w", err)
	}
	pins := resolved.Pins
	if len(pins) == 0 {
		pins = resolved.Object.Pins
	}
	for _, pin := range pins {
		name := firstNonEmpty(pin.Identity, pin.Package, pin.Description.Identity, packageNameFromURL(firstNonEmpty(pin.Location, pin.Repository)))
		if name == "" {
			continue
		}
		packages[name] = swiftPackage{
			Name:       name,
			Version:    firstNonEmpty(pin.State.Version, pin.State.Branch, pin.State.Revision),
			Repository: firstNonEmpty(pin.Location, pin.Repository),
			Revision:   pin.State.Revision,
		}
	}
	return packages, nil
}

func parsePackageSwift(raw string) map[string]swiftPackage {
	packages := make(map[string]swiftPackage)
	for _, match := range packageSwiftPattern.FindAllStringSubmatch(raw, -1) {
		repo := strings.TrimSpace(match[1])
		name := strings.TrimSpace(match[2])
		if name == "" {
			name = packageNameFromURL(repo)
		}
		if name == "" {
			continue
		}
		packages[name] = swiftPackage{Name: name, Repository: repo, Requirement: strings.TrimSpace(match[3]), Direct: true}
	}
	return packages
}

func readFirstExisting(workingDir string, names []string) ([]byte, string, error) {
	for _, name := range names {
		path := filepath.Join(workingDir, name)
		raw, err := readOptional(path)
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", name, err)
		}
		if len(raw) > 0 {
			return raw, path, nil
		}
	}
	return nil, "", nil
}

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return os.ReadFile(path)
}

func rootNode() *model.Package {
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemSwift),
		Name:        "root",
		BuildSystem: model.PackageManagerSwiftPM.Name(),
		Type:        "application",
		Language:    "swift",
	})
}

func packageNode(pkg swiftPackage) *model.Package {
	metadata := map[string]any{}
	if pkg.Repository != "" {
		metadata["repository"] = pkg.Repository
	}
	if pkg.Revision != "" {
		metadata["revision"] = pkg.Revision
	}
	if pkg.Requirement != "" {
		metadata["requirement"] = pkg.Requirement
	}
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemSwift),
		Name:        strings.TrimSpace(pkg.Name),
		Version:     strings.TrimSpace(pkg.Version),
		BuildSystem: model.PackageManagerSwiftPM.Name(),
		Type:        "package",
		Language:    "swift",
		PURL:        model.BuildPackageURL("swift", "", pkg.Name, pkg.Version),
		ResolvedURL: strings.TrimSpace(pkg.Repository),
		Metadata:    metadata,
	})
}

func packageNameFromURL(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".git")
	value = strings.TrimRight(value, "/")
	if value == "" {
		return ""
	}
	if i := strings.LastIndex(value, "/"); i >= 0 {
		return value[i+1:]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sortedNames(packages map[string]swiftPackage) []string {
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
