//go:build bomly_external_syft

package syft

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/sbom"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// ResolveGraph resolves a dependency graph by shelling out to the syft CLI binary.
func (d Detector) ResolveGraph(ctx context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	workingDir := syftWorkingDir(d.WorkingDir, req)
	target := workingDir
	if req.ExecutionTarget.Kind == detectors.ExecutionTargetContainerImage {
		target = req.ExecutionTarget.Location
	}
	if target == "" {
		target = "."
	}

	started := time.Now()
	logger.Debug("running external syft detector", zap.String("target", target))
	if req.EnrichmentEnabled {
		logger.Debug("enabling syft CLI detector enrichment", zap.Strings("enrich", syftDetectorEnrichmentValues))
	}

	var stdout, stderr bytes.Buffer
	cmd := system.Command("syft", syftCommandArgs(target, req)...)
	cmd.Dir = workingDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("syft CLI failed: %v (stderr: %s)", err, stderr.String()))
		return detectors.ResolveGraphResult{}, fmt.Errorf("run syft: %w", err)
	}

	doc, _, err := sbom.UnmarshalAutoJSON(stdout.Bytes())
	if err != nil {
		return detectors.ResolveGraphResult{}, fmt.Errorf("parse syft output: %w", err)
	}

	depsGraph, err := sbom.ToGraph(doc)
	if err != nil {
		return detectors.ResolveGraphResult{}, fmt.Errorf("convert syft sbom to graph: %w", err)
	}

	duration := time.Since(started)
	packageCount := 0
	if depsGraph != nil {
		packageCount = depsGraph.Size()
	}
	logger.Info(fmt.Sprintf("External syft detector found %d packages in %s", packageCount, logging.FormatDuration(duration)))

	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}
