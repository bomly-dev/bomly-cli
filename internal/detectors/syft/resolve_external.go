//go:build bomly_external_syft

package syft

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// ResolveGraph resolves a dependency graph by shelling out to the syft CLI binary.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	workingDir := syftWorkingDir(d.WorkingDir, req)
	target := workingDir
	if req.ExecutionTarget.Kind == sdk.ExecutionTargetContainerImage {
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
		return sdk.DetectionResult{}, fmt.Errorf("run syft: %w", err)
	}

	doc, _, err := sbom.UnmarshalAutoJSON(stdout.Bytes())
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("parse syft output: %w", err)
	}

	depsGraph, err := sbom.ToGraph(doc)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("convert syft sbom to graph: %w", err)
	}

	duration := time.Since(started)
	packageCount := 0
	if depsGraph != nil {
		packageCount = depsGraph.Size()
	}
	logger.Info(fmt.Sprintf("External syft detector found %d packages in %s", packageCount, logging.FormatDuration(duration)))

	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, supportedFilesForManager(req.PackageManager))),
	}, nil
}
