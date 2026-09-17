package npm

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// LockfileDetector resolves dependency graphs with npm.
type LockfileDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

var npmEvidencePatterns = []string{"npm-shrinkwrap.json", "package-lock.json"}
var npmManifestMetadataPatterns = []string{"npm-shrinkwrap.json", "package-lock.json", "package.json"}

// PackageManagerSupport returns npm package-manager discovery metadata.
func (d LockfileDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, npmEvidencePatterns...).WithMultiModule()}
}

// Ready reports whether npm is available.
func (d LockfileDetector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether an npm lockfile is present.
func (d LockfileDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().ProjectDir(req.ProjectPath)
	for _, name := range npmEvidencePatterns {
		exists, err := system.FileExists(filepath.Join(workingDir, name))
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the npm detector.
func (d LockfileDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameNPMLockfile,
		RemediationCapabilities: npmLockfileRemediationCapabilities(),
		Technique:               plugin.LockfileTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerNPM},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves an npm dependency graph from package-lock.json. A
// workspace lockfile yields one manifest entry per workspace member (the
// member's package.json plus its reachable dependency subtree) alongside the
// root entry.
func (d LockfileDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().ProjectDir(req.ProjectPath)
	graphs, err := depGraphFromNPMLockfile(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if _, err := node.AttachUnknownComponents(graphs.graph, graphs.rootID, d.Logger, detectors.NameNPMLockfile, graphs.lockfileName); err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	if err := node.AnnotateScopesFromPackageJSON(workingDir, graphs.graph); err != nil {
		return plugin.DetectionResult{}, err
	}
	AttachPackageLockPositionsForName(graphs.graph, workingDir, graphs.lockfileName)

	rootManifest := detectorkit.InferManifestMetadata(req, npmManifestMetadataPatterns)
	warnings := node.PackageManagerWarnings(workingDir, model.PackageManagerNPM,
		node.LockfileFormat{File: graphs.lockfileName, Version: strconv.Itoa(graphs.lockfileVersion)})
	if len(graphs.modules) == 0 {
		return detectors.Attributed(plugin.DetectionResult{
			Graphs:   model.SingleGraphContainer(graphs.graph, rootManifest),
			Warnings: warnings,
		}, npmDeclarations(graphs)...), nil
	}

	entries, err := workspaceGraphEntries(graphs, rootManifest)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("npm lockfile parser detector: %w", err)
	}
	req.DetectorLogger(d.Logger).Info("npm lockfile detector resolved workspace members",
		zap.Int("members", len(graphs.modules)))
	return detectors.Attributed(plugin.DetectionResult{
		Graphs: &model.GraphContainer{Entries: entries},
	}, npmDeclarations(graphs)...), nil
}

// npmDeclarations reports what each module root's own package.json declared,
// so a site can carry the scope its module gave it rather than the union
// across every member. A workspace member declaring a package under
// devDependencies and a sibling reaching the same package at runtime is the
// case the union cannot express.
func npmDeclarations(graphs npmLockfileGraphs) []detectors.ModuleDeclarations {
	declarations := make([]detectors.ModuleDeclarations, 0, len(graphs.modules)+1)
	declarations = append(declarations, detectors.ModuleDeclarations{ModuleRoot: ".", Scopes: graphs.rootDeclared})
	for _, module := range graphs.modules {
		declarations = append(declarations, detectors.ModuleDeclarations{ModuleRoot: module.dir, Scopes: module.declared})
	}
	return declarations
}

// workspaceGraphEntries partitions a workspace lockfile graph into the root
// manifest entry (root node plus its own dependency subtree) and one entry
// per workspace member (member root plus its reachable subtree, manifest
// path "<member-dir>/package.json").
func workspaceGraphEntries(graphs npmLockfileGraphs, rootManifest model.ManifestMetadata) ([]model.GraphEntry, error) {
	entries := make([]model.GraphEntry, 0, len(graphs.modules)+1)
	rootGraph, err := detectorkit.SubgraphFrom(graphs.graph, graphs.rootID)
	if err != nil {
		return nil, fmt.Errorf("extract workspace root graph: %w", err)
	}
	entries = append(entries, model.GraphEntry{Graph: rootGraph, Manifest: rootManifest})
	for _, module := range graphs.modules {
		moduleGraph, err := detectorkit.SubgraphFrom(graphs.graph, module.rootID)
		if err != nil {
			return nil, fmt.Errorf("extract workspace member graph %q: %w", module.dir, err)
		}
		entries = append(entries, model.GraphEntry{
			Graph: moduleGraph,
			Manifest: model.ManifestMetadata{
				Path: module.dir + "/package.json",
				Kind: model.ManifestKind("package.json"),
			},
		})
	}
	return entries, nil
}

func (d LockfileDetector) base() node.BaseDetector {
	return node.BaseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}
