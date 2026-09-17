package sbt

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Detector resolves Scala sbt dependency declarations from committed build files.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
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
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerSBT, evidencePatterns...).WithMultiModule()}
}

// Ready reports whether committed sbt files can be parsed.
func (d Detector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether sbt build files are present.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
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
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:  []string{"target"},
		Name:                detectors.NameSBT,
		Technique:           plugin.ManifestTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemScala, model.EcosystemMaven},
		SupportedManagers:   []model.PackageManager{model.PackageManagerSBT},
		Tags:                []string{"graph-resolution", "component-targeting", "manifest-parsing", "scope-annotation"},
	}
}

// ResolveGraph resolves an sbt dependency graph.
func (d Detector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	g, err := depGraphFromSBTFiles(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachSBTPositions(g, workingDir)
	return detectors.Attributed(plugin.DetectionResult{Graphs: model.SingleGraphContainer(g, detectorkit.InferManifestMetadata(req, evidencePatterns))}), nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() plugin.Detector {
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
	root, err := rootNode()
	if err != nil {
		return nil, err
	}
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	seen := make(map[string]struct{}, len(packages))
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Org+packages[i].Name+packages[i].Version < packages[j].Org+packages[j].Name+packages[j].Version
	})
	for _, pkg := range packages {
		node, err := packageNode(pkg)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[node.NodeID()]; ok {
			continue
		}
		seen[node.NodeID()] = struct{}{}
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
		if err := g.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add sbt root dependency %q: %w", node.NodeID(), err)
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
	return system.ReadRepositoryFile(path)
}

func rootNode() (*model.ModuleNode, error) {
	return model.NewModuleNode("build.sbt", model.Coordinates{Ecosystem: model.EcosystemScala,
		Name:           "root",
		PackageManager: model.PackageManagerSBT,
		Type:           model.PackageTypeApplication,
		Language:       "scala"})

}

func packageNode(pkg sbtPackage) (*model.DependencyNode, error) {
	node, err := model.NewDependencyNode(model.Coordinates{Ecosystem: model.EcosystemScala,
		Org:            strings.TrimSpace(pkg.Org),
		Name:           strings.TrimSpace(pkg.Name),
		Version:        strings.TrimSpace(pkg.Version),
		PackageManager: model.PackageManagerSBT,
		Type:           model.PackageTypePackage,
		Language:       "scala",
		PURL:           model.BuildPackageURLFor(model.EcosystemScala, model.PackageManagerSBT, pkg.Org, pkg.Name, pkg.Version)})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}

	if pkg.Scope != "" {
		node.AddScope(pkg.Scope)
	}
	return node, nil
}

func addNodeIfMissing(g *model.Graph, node *model.DependencyNode) error {
	_, err := detectorkit.EnsureNode(g, node)
	return err
}
