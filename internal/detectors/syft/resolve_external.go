//go:build bomly_external_syft

package syft

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-sdk"
	detectors "github.com/bomly-dev/bomly-sdk/detectorkit"
	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"
)

// ResolveGraph resolves a dependency graph by shelling out to the syft CLI binary.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
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
	args := syftCommandArgs(target, req)
	logger.Debug("running external syft detector", logkit.CommandFields("syft", args, workingDir)...)
	if req.EnrichmentEnabled {
		logger.Debug("enabling syft CLI detector enrichment", zap.Strings("enrich", syftDetectorEnrichmentValues))
	}

	var stdout bytes.Buffer
	commandStderr := logkit.NewCommandStderr(req.Stderr, req.Verbose)
	cmd := system.Command("syft", args...)
	cmd.Dir = workingDir
	cmd.Stdout = &stdout
	cmd.Stderr = commandStderr

	if err := cmd.Run(); err != nil {
		logger.Warn("syft CLI failed", zap.Error(err), zap.Int64("stderr_bytes", commandStderr.ByteCount()))
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
