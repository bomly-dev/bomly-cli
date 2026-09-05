package sbom

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
)

const maxSBOMFileBytes int64 = 256 << 20

// Detector resolves graphs from explicit SBOM files using Bomly's first-party decoders.
type Detector struct {
	Logger *zap.Logger
}

var evidencePatterns = []string{"*.syft.json", "*.bom.*", "*.bom", "bom", "*.sbom.*", "*.sbom", "sbom", "*.cdx.*", "*.cdx", "*.spdx.*", "*.spdx"}

// PackageManagerSupport returns SBOM package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerSBOM, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether the request targets an explicit SBOM file.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx

	if req.PackageManager != sdk.PackageManagerSBOM || req.ExecutionTarget.Kind != sdk.ExecutionTargetFilesystem {
		return false, nil
	}

	info, err := os.Stat(req.ExecutionTarget.Location)
	if err != nil {
		return false, nil
	}
	return !info.IsDir(), nil
}

// Descriptor describes the first-party SBOM detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSBOM,
		Technique:           sdk.SBOMTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemSBOM},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSBOM},
		Tags:                []string{"graph-resolution", "sbom-import"},
	}
}

// ResolveGraph resolves a dependency graph from a supported SBOM file.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	sbomPath := req.ExecutionTarget.Location
	if sbomPath == "" {
		sbomPath = req.ProjectPath
	}
	data, err := system.ReadFileLimit(sbomPath, maxSBOMFileBytes)
	if err != nil {
		if errors.Is(err, system.ErrInputTooLarge) {
			return sdk.DetectionResult{}, fmt.Errorf("sbom file %q exceeds the 256 MiB limit: %w", sbomPath, system.ErrInputTooLarge)
		}
		return sdk.DetectionResult{}, fmt.Errorf("read sbom file %q: %w", sbomPath, err)
	}

	doc, target, err := sbom.UnmarshalAutoJSON(data)
	if err != nil {
		switch {
		case errors.Is(err, sbom.ErrMalformedJSON):
			return sdk.DetectionResult{}, fmt.Errorf("parse sbom file %q: %w", sbomPath, err)
		case errors.Is(err, sbom.ErrUnsupportedFormat):
			return sdk.DetectionResult{}, fmt.Errorf("detect sbom format for %q: %w", sbomPath, err)
		default:
			return sdk.DetectionResult{}, fmt.Errorf("decode sbom file %q: %w", sbomPath, err)
		}
	}

	depsGraph, err := sbom.ToGraph(doc)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("convert sbom %q to graph: %w", sbomPath, err)
	}
	graphs := sdk.SingleGraphContainer(depsGraph, detectorkit.InferManifestMetadata(req, evidencePatterns))
	// What the document said about itself rides the entry it became, so a
	// later export can restate it instead of crediting only Bomly for a
	// document Bomly only converted (ADR-0037).
	if assertions := doc.Assertions; !assertions.IsEmpty() && len(graphs.Entries) == 1 {
		graphs.Entries[0].Document = &assertions
	}

	logger.Debug("resolved explicit sbom file", zap.String("path", sbomPath), zap.String("format", string(target)))
	return sdk.DetectionResult{
		SubprojectInfo: req.Subproject,
		DetectorName:   d.Descriptor().Name,
		Technique:      d.Descriptor().Technique,
		Graphs:         normalizeSBOMGraphContainer(normalizeSBOMManifestMetadata(graphs, req)),
	}, nil
}

func normalizeSBOMManifestMetadata(container *sdk.GraphContainer, req sdk.DetectionRequest) *sdk.GraphContainer {
	if container == nil || len(container.Entries) == 0 {
		return container
	}
	normalized := &sdk.GraphContainer{Entries: make([]sdk.GraphEntry, 0, len(container.Entries))}
	defaultManifest := detectorkit.InferManifestMetadata(req, evidencePatterns)
	for _, entry := range container.Entries {
		manifest := entry.Manifest
		if manifest.Path == "" {
			manifest.Path = defaultManifest.Path
		}
		if manifest.Kind == "" {
			manifest.Kind = defaultManifest.Kind
		}
		normalized.Entries = append(normalized.Entries, sdk.GraphEntry{
			Graph:    entry.Graph,
			Manifest: manifest,
			Document: entry.Document,
		})
	}
	return normalized
}

func normalizeSBOMGraphContainer(container *sdk.GraphContainer) *sdk.GraphContainer {
	if container == nil {
		return nil
	}
	normalized := &sdk.GraphContainer{Entries: make([]sdk.GraphEntry, 0, len(container.Entries))}
	for _, entry := range container.Entries {
		normalizedGraph, err := normalizeSBOMGraphIdentity(entry.Graph)
		if err != nil {
			normalizedGraph = entry.Graph
		}
		normalized.Entries = append(normalized.Entries, sdk.GraphEntry{
			Graph:    normalizedGraph,
			Manifest: entry.Manifest,
			Document: entry.Document,
		})
	}
	return normalized
}

func normalizeSBOMGraphIdentity(src *sdk.Graph) (*sdk.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := sdk.NewWithCapacity(src.Size())
	idMap := make(map[string]string, src.Size())
	for _, pkg := range src.DependencyNodes() {
		if pkg == nil {
			continue
		}
		// Nothing to rewrite: a node's ID is its canonical package URL,
		// minted by the constructor (ADR-0041). The PURL-then-StableID
		// fallback this ran is the identity machinery that replaced.
		clone := pkg.Clone()
		if _, exists := normalized.Node(clone.NodeID()); !exists {
			if err := normalized.AddNode(clone); err != nil {
				return nil, fmt.Errorf("normalize sbom package %q: %w", clone.NodeID(), err)
			}
		}
		idMap[pkg.NodeID()] = clone.NodeID()
	}

	for _, pkg := range src.DependencyNodes() {
		if pkg == nil {
			continue
		}
		fromID := idMap[pkg.NodeID()]
		if fromID == "" {
			continue
		}
		deps, err := src.DirectDependencies(pkg.NodeID())
		if err != nil {
			return nil, fmt.Errorf("normalize sbom dependencies for %q: %w", pkg.NodeID(), err)
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			toID := idMap[dep.NodeID()]
			if toID == "" || toID == fromID {
				continue
			}
			if err := normalized.AddEdge(fromID, toID); err != nil {
				return nil, fmt.Errorf("normalize sbom dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}
	return normalized, nil
}
