//go:build bomly_builtin_syft

package syft

import (
	"context"
	"fmt"
	"io"
	"time"

	syftlib "github.com/anchore/syft/syft"
	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	_ "github.com/glebarez/sqlite" // register "sqlite" driver required by syft's RPM cataloger
	"go.uber.org/zap"
)

// ResolveGraph resolves a dependency graph by invoking the Syft Go library.
func (d Detector) ResolveGraph(ctx context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	workingDir := syftWorkingDir(d.WorkingDir, req)

	graphs, err := d.resolveGraph(ctx, req.ExecutionTarget, req.PackageManager, workingDir, req.Stderr)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}

	return detectors.ResolveGraphResult{Graphs: graphs}, nil
}

func (d Detector) resolveGraph(ctx context.Context, executionTarget detectors.ExecutionTarget, packageManager detectors.PackageManager, workingDir string, stderr io.Writer) (*detectors.GraphContainer, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	_ = stderr

	target, sourceMode, sourceConfig := syftSourceInput(executionTarget, workingDir)
	started := time.Now()
	logger.Debug(
		"running syft detector",
		zap.String("target", target),
		zap.String("target_kind", string(executionTarget.Kind)),
		zap.String("syft_source_mode", sourceMode),
	)

	src, err := syftlib.GetSource(ctx, target, sourceConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("Syft source detection failed: %v", err))
		logger.Debug("syft source detection failed", zap.Error(err))
		return nil, fmt.Errorf("create syft source: %w", err)
	}
	defer func() {
		_ = src.Close()
	}()

	syftSBOM, err := syftlib.CreateSBOM(ctx, src, syftlib.DefaultCreateSBOMConfig())
	if err != nil {
		logger.Error(fmt.Sprintf("Syft SBOM generation failed: %v", err))
		logger.Debug("syft sbom generation failed", zap.Error(err))
		return nil, fmt.Errorf("create syft sbom: %w", err)
	}

	graphs, err := graphContainerFromSyftSBOM(syftSBOM, packageManager)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map Syft SBOM to a dependency graph: %v", err))
		logger.Debug("syft sbom mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	graphCount := 0
	packageCount := 0
	if graphs != nil {
		graphCount = graphs.Len()
		for _, entry := range graphs.Entries {
			if entry.Graph != nil {
				packageCount += entry.Graph.Size()
			}
		}
	}
	logger.Info(fmt.Sprintf("Syft detector found %d package instances across %d path(s) in %s", packageCount, graphCount, logging.FormatDuration(duration)))

	return graphs, nil
}

func syftSourceInput(executionTarget detectors.ExecutionTarget, workingDir string) (string, string, *syftlib.GetSourceConfig) {
	target := workingDir
	sourceMode := "dir"
	if target == "" {
		target = "."
	}
	config := syftlib.DefaultGetSourceConfig()

	switch executionTarget.Kind {
	case detectors.ExecutionTargetContainerImage:
		if executionTarget.Location != "" {
			target = executionTarget.Location
		}
		sourceMode = "container"
	case detectors.ExecutionTargetFilesystem:
		if executionTarget.Location != "" {
			target = executionTarget.Location
		}
		if isSingleFileTarget(target) {
			config = config.WithSources("file")
			sourceMode = "file"
		} else {
			config = config.WithSources("dir")
			sourceMode = "dir"
		}
	default:
		if executionTarget.Location != "" {
			target = executionTarget.Location
		}
		config = config.WithSources("dir")
	}

	return target, sourceMode, config
}
