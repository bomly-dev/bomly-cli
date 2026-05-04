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
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves Scala sbt dependency declarations from committed build files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var evidencePatterns = []string{"build.sbt", "project/plugins.sbt", "project/build.properties"}

type sbtPackage struct {
	Org     string
	Name    string
	Version string
	Scope   model.Scope
}

var sbtDependencyPattern = regexp.MustCompile(`"([^"]+)"\s*%{1,2}\s*"([^"]+)"\s*%\s*"([^"]+)"(?:\s*%\s*"?([^"\s,)]+)"?)?`)

// PackageManagerSupport returns sbt package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerSBT, evidencePatterns...)}
}

// Ready reports whether committed sbt files can be parsed.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether sbt build files are present.
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

// Descriptor describes the sbt detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameSBT,
		Enabled:             true,
		ComponentType:       model.NativeComponent,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemScala, model.EcosystemMaven},
		SupportedManagers:   []model.PackageManager{model.PackageManagerSBT},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "manifest-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves an sbt dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	g, err := depGraphFromSBTFiles(workingDir)
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

func depGraphFromSBTFiles(workingDir string) (*model.Graph, error) {
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
	g := model.New()
	root := rootNode()
	if err := g.AddPackage(root); err != nil {
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
		if err := g.AddDependency(root.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add sbt root dependency %q: %w", node.ID, err)
		}
	}
	return g, nil
}

func parseSBTDependencies(raw string) []sbtPackage {
	matches := sbtDependencyPattern.FindAllStringSubmatch(raw, -1)
	packages := make([]sbtPackage, 0, len(matches))
	for _, match := range matches {
		scope := model.ScopeRuntime
		config := strings.ToLower(strings.Trim(match[4], `"`))
		if strings.Contains(config, "test") || strings.Contains(config, "provided") {
			scope = model.ScopeDevelopment
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

func rootNode() *model.Package {
	return model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemScala),
		Name:        "root",
		BuildSystem: model.PackageManagerSBT.Name(),
		Type:        "application",
		Language:    "scala",
	})
}

func packageNode(pkg sbtPackage) *model.Package {
	node := model.NewPackage(model.Package{
		Ecosystem:   string(model.EcosystemScala),
		Org:         strings.TrimSpace(pkg.Org),
		Name:        strings.TrimSpace(pkg.Name),
		Version:     strings.TrimSpace(pkg.Version),
		BuildSystem: model.PackageManagerSBT.Name(),
		Type:        "package",
		Language:    "scala",
		PURL:        model.BuildPackageURL("maven", pkg.Org, pkg.Name, pkg.Version),
	})
	if pkg.Scope != "" {
		model.MergePackageScope(node, pkg.Scope)
	}
	return node
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
