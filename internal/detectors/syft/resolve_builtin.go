//go:build !bomly_external_syft

package syft

import (
	"context"
	"fmt"
	"io"
	"time"

	syftlib "github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/sdk"
	_ "github.com/glebarez/sqlite" // register "sqlite" driver required by syft's RPM cataloger
	"go.uber.org/zap"
)

// ResolveGraph resolves a dependency graph by invoking the Syft Go library.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := syftWorkingDir(d.WorkingDir, req)

	graphs, err := d.resolveGraph(ctx, req, workingDir, req.Stderr)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	return sdk.DetectionResult{Graphs: graphs}, nil
}

func (d Detector) resolveGraph(ctx context.Context, req sdk.DetectionRequest, workingDir string, stderr io.Writer) (*sdk.GraphContainer, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	_ = stderr

	target, sourceMode, sourceConfig := syftSourceInput(req.ExecutionTarget, workingDir)
	started := time.Now()
	logger.Debug(
		"running syft detector",
		zap.String("target", target),
		zap.String("target_kind", string(req.ExecutionTarget.Kind)),
		zap.String("syft_source_mode", sourceMode),
	)
	if req.EnrichmentEnabled {
		logger.Debug("enabling offline-safe syft detector enrichment")
	}

	src, err := syftlib.GetSource(ctx, target, sourceConfig)
	if err != nil {
		logger.Warn(fmt.Sprintf("Syft source detection failed: %v", err))
		logger.Debug("syft source detection failed", zap.Error(err))
		return nil, fmt.Errorf("create syft source: %w", err)
	}
	defer func() {
		_ = src.Close()
	}()

	syftSBOM, err := syftlib.CreateSBOM(ctx, src, syftCreateSBOMConfig(req))
	if err != nil {
		logger.Warn(fmt.Sprintf("Syft SBOM generation failed: %v", err))
		logger.Debug("syft sbom generation failed", zap.Error(err))
		return nil, fmt.Errorf("create syft sbom: %w", err)
	}

	graphs, err := graphContainerFromSyftSBOM(syftSBOM, req.PackageManager)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to map Syft SBOM to a dependency graph: %v", err))
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

func syftCreateSBOMConfig(req sdk.DetectionRequest) *syftlib.CreateSBOMConfig {
	cfg := syftlib.DefaultCreateSBOMConfig()
	cfg.CatalogerSelection = syftCatalogerSelection(req)
	if !req.EnrichmentEnabled {
		return cfg
	}

	packages := cfg.Packages
	packages.Golang = packages.Golang.
		WithSearchLocalModCacheLicenses(true).
		WithSearchLocalVendorLicenses(true)
	packages.JavaArchive = packages.JavaArchive.
		WithUseMavenLocalRepository(true).
		WithUseNetwork(false)
	cfg.Packages = pkgcataloging.Config{
		Binary:      packages.Binary,
		Dotnet:      packages.Dotnet,
		Golang:      packages.Golang,
		JavaArchive: packages.JavaArchive,
		JavaScript:  packages.JavaScript,
		LinuxKernel: packages.LinuxKernel,
		Nix:         packages.Nix,
		Python:      packages.Python,
	}
	return cfg
}

func syftSourceInput(executionTarget sdk.ExecutionTarget, workingDir string) (string, string, *syftlib.GetSourceConfig) {
	target := workingDir
	sourceMode := "dir"
	if target == "" {
		target = "."
	}
	config := syftlib.DefaultGetSourceConfig()

	switch executionTarget.Kind {
	case sdk.ExecutionTargetContainerImage:
		if executionTarget.Location != "" {
			target = executionTarget.Location
		}
		sourceMode = "container"
	case sdk.ExecutionTargetFilesystem:
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
