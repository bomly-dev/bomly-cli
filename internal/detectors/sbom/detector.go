package sbom

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves graphs from explicit SBOM files using Bomly's first-party decoders.
type Detector struct {
	Logger *zap.Logger
}

var evidencePatterns = []string{"*.syft.json", "*.bom.*", "*.bom", "bom", "*.sbom.*", "*.sbom", "sbom", "*.cdx.*", "*.cdx", "*.spdx.*", "*.spdx"}

// PackageManagerSupport returns SBOM package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerSBOM, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether the request targets an explicit SBOM file.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx

	if req.PackageManager != model.PackageManagerSBOM || req.ExecutionTarget.Kind != model.ExecutionTargetFilesystem {
		return false, nil
	}

	info, err := os.Stat(req.ExecutionTarget.Location)
	if err != nil {
		return false, nil
	}
	return !info.IsDir(), nil
}

// Descriptor describes the first-party SBOM detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameSBOM,
		Enabled:             true,
		ComponentType:       model.NativeComponent,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemSBOM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerSBOM},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "sbom-import"},
	}
}

// ResolveGraph resolves a dependency graph from a supported SBOM file.
func (d Detector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	sbomPath := req.ExecutionTarget.Location
	if sbomPath == "" {
		sbomPath = req.ProjectPath
	}
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("read sbom file %q: %w", sbomPath, err)
	}

	doc, target, err := sbom.UnmarshalAutoJSON(data)
	if err != nil {
		switch {
		case err == sbom.ErrMalformedJSON:
			return model.DetectionResult{}, fmt.Errorf("parse sbom file %q: %w", sbomPath, err)
		case err == sbom.ErrUnsupportedFormat:
			return model.DetectionResult{}, fmt.Errorf("detect sbom format for %q: %w", sbomPath, err)
		default:
			return model.DetectionResult{}, fmt.Errorf("decode sbom file %q: %w", sbomPath, err)
		}
	}

	var graphs *model.GraphContainer
	switch target {
	case sbom.TargetSyftJSON:
		var syftErr error
		graphs, syftErr = decodeSyftJSONGraphs(data, sbomPath)
		if syftErr != nil {
			return model.DetectionResult{}, syftErr
		}
	default:
		depsGraph, err := sbom.ToGraph(doc)
		if err != nil {
			return model.DetectionResult{}, fmt.Errorf("convert sbom %q to graph: %w", sbomPath, err)
		}
		graphs = model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, evidencePatterns))
	}

	logger.Debug("resolved explicit sbom file", zap.String("path", sbomPath), zap.String("format", string(target)))
	return model.DetectionResult{
		SubprojectInfo: req.Subproject,
		DetectorName:   d.Descriptor().Name,
		ComponentType:  d.Descriptor().ComponentType,
		Graphs:         normalizeSBOMGraphContainer(normalizeSBOMManifestMetadata(graphs, req)),
	}, nil
}

func normalizeSBOMManifestMetadata(container *model.GraphContainer, req model.DetectionRequest) *model.GraphContainer {
	if container == nil || len(container.Entries) == 0 {
		return container
	}
	normalized := &model.GraphContainer{Entries: make([]model.GraphEntry, 0, len(container.Entries))}
	defaultManifest := detectors.InferManifestMetadata(req, evidencePatterns)
	for _, entry := range container.Entries {
		manifest := entry.Manifest
		if manifest.Path == "" {
			manifest.Path = defaultManifest.Path
		}
		if manifest.Kind == "" {
			manifest.Kind = defaultManifest.Kind
		}
		normalized.Entries = append(normalized.Entries, model.GraphEntry{
			Graph:    entry.Graph,
			Manifest: manifest,
		})
	}
	return normalized
}

func normalizeSBOMGraphContainer(container *model.GraphContainer) *model.GraphContainer {
	if container == nil {
		return nil
	}
	normalized := &model.GraphContainer{Entries: make([]model.GraphEntry, 0, len(container.Entries))}
	for _, entry := range container.Entries {
		normalizedGraph, err := normalizeSBOMGraphIdentity(entry.Graph)
		if err != nil {
			normalizedGraph = entry.Graph
		}
		normalized.Entries = append(normalized.Entries, model.GraphEntry{
			Graph:    normalizedGraph,
			Manifest: entry.Manifest,
		})
	}
	return normalized
}

func normalizeSBOMGraphIdentity(src *model.Graph) (*model.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := model.NewWithCapacity(src.Size())
	idMap := make(map[string]string, src.Size())
	for _, pkg := range src.Packages() {
		if pkg == nil {
			continue
		}
		clone := pkg.Clone()
		if purl := strings.TrimSpace(clone.PURL); purl != "" {
			clone.ID = purl
		} else if stableID := strings.TrimSpace(clone.StableID()); stableID != "" {
			clone.ID = stableID
		}
		if clone.ID == "" {
			clone.ID = pkg.ID
		}
		if _, exists := normalized.Package(clone.ID); !exists {
			if err := normalized.AddPackage(clone); err != nil {
				return nil, fmt.Errorf("normalize sbom package %q: %w", clone.ID, err)
			}
		}
		idMap[pkg.ID] = clone.ID
	}

	for _, pkg := range src.Packages() {
		if pkg == nil {
			continue
		}
		fromID := idMap[pkg.ID]
		if fromID == "" {
			continue
		}
		deps, err := src.Dependencies(pkg.ID)
		if err != nil {
			return nil, fmt.Errorf("normalize sbom dependencies for %q: %w", pkg.ID, err)
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			toID := idMap[dep.ID]
			if toID == "" || toID == fromID {
				continue
			}
			if err := normalized.AddDependency(fromID, toID); err != nil {
				return nil, fmt.Errorf("normalize sbom dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}
	return normalized, nil
}
