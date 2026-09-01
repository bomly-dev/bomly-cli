package swiftpm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
)

// Detector resolves Swift Package Manager dependency graphs from Package.resolved.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// resolvedCandidates lists every place a Package.resolved can live, in the
// order a project is most likely to keep one. It is the single list: the
// fallback detector reads it, the native detector reads it back to pin origins,
// evidence detection is built from it, and position attachment walks it. They
// had drifted into three different lists, so a project whose only lockfile sat
// in the Xcode workspace was recognized for line numbers but not for reading.
var resolvedCandidates = []string{
	"Package.resolved",
	".package.resolved",
	filepath.Join(".swiftpm", "xcode", "package.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"),
	filepath.Join("project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"),
}

// evidencePatterns is what makes this detector applicable: any lockfile
// location, or a manifest with no lockfile beside it.
var evidencePatterns = append(append([]string{}, resolvedCandidates...), "Package.swift")

type packageResolved struct {
	Object struct {
		Pins []resolvedPin `json:"pins"`
	} `json:"object"`
	Pins []resolvedPin `json:"pins"`
}

type resolvedPin struct {
	Identity    string        `json:"identity"`
	Kind        string        `json:"kind"`
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
	SourceKind  string
	Repository  string
	Revision    string
	Requirement string
	Direct      bool
}

var packageSwiftPattern = regexp.MustCompile(`\.package\s*\([^)]*(?:url:\s*"([^"]+)"|name:\s*"([^"]+)")[^)]*(?:from:|exact:|branch:|revision:)\s*"([^"]+)"`)

// PackageManagerSupport returns SwiftPM package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerSwiftPM, evidencePatterns...)}
}

// Ready reports whether committed SwiftPM files can be parsed.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether SwiftPM files are present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
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
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSwiftPM,
		Technique:           sdk.LockfileTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSwift},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSwiftPM},
		Tags:                []string{"graph-resolution", "component-targeting", "lockfile-parsing"},
	}
}

// ResolveGraph resolves a SwiftPM dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	resolvedRaw, resolvedPath, err := readFirstExisting(workingDir, resolvedCandidates)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	manifestRaw, err := readOptional(filepath.Join(workingDir, "Package.swift"))
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read Package.swift: %w", err)
	}
	g, err := depGraphFromSwiftPM(resolvedRaw, manifestRaw)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	metadataPatterns := evidencePatterns
	if resolvedPath != "" {
		metadataPatterns = append([]string{filepath.Base(resolvedPath)}, evidencePatterns...)
	}
	AttachPackageResolvedPositions(g, workingDir)
	return sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, metadataPatterns))}, nil
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

func depGraphFromSwiftPM(resolvedRaw, manifestRaw []byte) (*sdk.Graph, error) {
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
	g := sdk.New()
	root, err := rootNode()
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, name := range sortedNames(packages) {
		pkg := packages[name]
		node, err := packageNode(pkg)
		if err != nil {
			return nil, err
		}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add SwiftPM root dependency %q: %w", node.NodeID(), err)
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
			SourceKind: pin.Kind,
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
	return system.ReadRepositoryFile(path)
}

func rootNode() (*sdk.ModuleNode, error) {
	return sdk.NewModuleNode("Package.swift", sdk.Coordinates{Ecosystem: sdk.EcosystemSwift,
		Name:           "root",
		PackageManager: sdk.PackageManagerSwiftPM,
		Type:           sdk.PackageTypeApplication,
		Language:       "swift"})

}

func packageNode(pkg swiftPackage) (*sdk.DependencyNode, error) {
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
	namespace, name := packageIdentity(pkg.Repository, pkg.Name)
	node, err := detectors.NewDependencyOrGeneric(sdk.Coordinates{Ecosystem: sdk.EcosystemSwift,
		Org:            namespace,
		Name:           name,
		Version:        strings.TrimSpace(pkg.Version),
		PackageManager: sdk.PackageManagerSwiftPM,
		Type:           sdk.PackageTypePackage,
		Language:       "swift",
		PURL:           sdk.BuildPackageURL("swift", namespace, name, pkg.Version)})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}
	node.Source = swiftDependencySource(pkg.SourceKind, pkg.Repository)
	node.ResolvedURL = strings.TrimSpace(pkg.Repository)
	node.Metadata = metadata

	if swiftDependencySource(pkg.SourceKind, pkg.Repository) == sdk.DependencySourceGit {
		// Source-control pins name the repository and the commit SwiftPM
		// resolved. Registry pins are identity-only, and local packages
		// point at a checkout on this machine.
		if origin := sdk.RepositoryOrigin(pkg.Repository, pkg.Revision); origin != nil {
			node.Origins = sdk.MergeOrigins(node.Origins, []sdk.DependencyOrigin{*origin})
		}
	}

	// SwiftPM does not distinguish dev scope; all packages are runtime.
	node.AddScope(sdk.ScopeRuntime)
	return node, nil
}

func swiftDependencySource(kind, location string) sdk.DependencySource {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "registry":
		return sdk.DependencySourceRegistry
	case "remotesourcecontrol":
		return sdk.DependencySourceGit
	case "localsourcecontrol", "filesystem":
		return sdk.DependencySourceFile
	case "":
		if strings.TrimSpace(location) != "" {
			// Package.resolved v1 predates the kind field. Its repositoryURL
			// field is source-control evidence, not an arbitrary download URL.
			return sdk.DependencySourceGit
		}
	}
	return ""
}

func swiftSourceKindForLocation(location string) string {
	location = strings.TrimSpace(location)
	switch {
	case location == "":
		return ""
	case strings.HasPrefix(strings.ToLower(location), "file:"),
		filepath.IsAbs(location),
		strings.HasPrefix(location, "./"),
		strings.HasPrefix(location, "../"):
		return "localSourceControl"
	default:
		return "remoteSourceControl"
	}
}

func packageIdentity(repository, fallbackName string) (string, string) {
	name := strings.TrimSpace(fallbackName)
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return "", name
	}
	parsed, err := url.Parse(repository)
	if err != nil || parsed.Host == "" {
		return "", name
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	repoPath := strings.Trim(strings.TrimSuffix(parsed.Path, ".git"), "/")
	if repoPath == "" {
		return "", name
	}
	parts := strings.Split(repoPath, "/")
	if len(parts) == 0 {
		return "", name
	}
	name = parts[len(parts)-1]
	namespaceParts := append([]string{host}, parts[:len(parts)-1]...)
	return strings.Join(namespaceParts, "/"), name
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

func addNodeIfMissing(g *sdk.Graph, node *sdk.DependencyNode) error {
	_, err := detectors.EnsureNode(g, node)
	return err
}
