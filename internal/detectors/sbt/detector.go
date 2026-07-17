package sbt

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

// Detector resolves Scala sbt dependency declarations from committed build files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"build.sbt", "project/plugins.sbt", "project/build.properties"}

type sbtPackage struct {
	Org     string
	Name    string
	Version string
	Scope   sdk.Scope
}

var sbtDependencyPattern = regexp.MustCompile(`"([^"]+)"\s*%{1,2}\s*"([^"]+)"\s*%\s*"([^"]+)"(?:\s*%\s*"?([^"\s,)]+)"?)?`)

// PackageManagerSupport returns sbt package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerSBT, evidencePatterns...).WithMultiModule()}
}

// Ready reports whether committed sbt files can be parsed.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether sbt build files are present.
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

// Descriptor describes the sbt detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:  []string{"target"},
		Name:                detectors.NameSBT,
		Technique:           sdk.ManifestTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemScala, sdk.EcosystemMaven},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSBT},
		Tags:                []string{"graph-resolution", "component-targeting", "manifest-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves an sbt dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	g, err := depGraphFromSBTFiles(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	AttachSBTPositions(g, workingDir)
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

func depGraphFromSBTFiles(workingDir string) (*sdk.Graph, error) {
	packages := make([]sbtPackage, 0)
	for _, name := range []string{"build.sbt", "project/plugins.sbt"} {
		raw, err := readOptional(filepath.Join(workingDir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		packages = append(packages, parseSBTDependencies(string(raw))...)
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("sbt files do not contain any dependencies")
	}
	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	seen := make(map[string]struct{}, len(packages))
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Org+packages[i].Name+packages[i].Version < packages[j].Org+packages[j].Name+packages[j].Version
	})
	for _, pkg := range packages {
		node := packageNode(pkg)
		if _, ok := seen[node.ID]; ok {
			continue
		}
		seen[node.ID] = struct{}{}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add sbt root dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func parseSBTDependencies(raw string) []sbtPackage {
	matches := sbtDependencyPattern.FindAllStringSubmatch(raw, -1)
	packages := make([]sbtPackage, 0, len(matches))
	for _, match := range matches {
		scope := sdk.ScopeRuntime
		config := strings.ToLower(strings.Trim(match[4], `"`))
		if strings.Contains(config, "test") || strings.Contains(config, "provided") {
			scope = sdk.ScopeDevelopment
		}
		packages = append(packages, sbtPackage{
			Org:     strings.TrimSpace(match[1]),
			Name:    strings.TrimSpace(match[2]),
			Version: strings.TrimSpace(match[3]),
			Scope:   scope,
		})
	}
	return packages
}

func readOptional(path string) ([]byte, error) {
	ok, err := system.FileExists(path)
	if err != nil || !ok {
		return nil, err
	}
	return os.ReadFile(path)
}

func rootNode() *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemScala,
		Name:           "root",
		PackageManager: sdk.PackageManagerSBT,
		Type:           sdk.PackageTypeApplication,
		FirstParty:     true,
		Language:       "scala"},
	})

}

func packageNode(pkg sbtPackage) *sdk.Dependency {
	node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemScala,
		Org:            strings.TrimSpace(pkg.Org),
		Name:           strings.TrimSpace(pkg.Name),
		Version:        strings.TrimSpace(pkg.Version),
		PackageManager: sdk.PackageManagerSBT,
		Type:           sdk.PackageTypePackage,
		Language:       "scala",
		PURL:           sdk.BuildPackageURL("maven", pkg.Org, pkg.Name, pkg.Version)},
	})

	if pkg.Scope != "" {
		node.AddScope(pkg.Scope)
	}
	return node
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
