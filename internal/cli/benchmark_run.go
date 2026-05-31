package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	scanengine "github.com/bomly-dev/bomly-cli/internal/engine/scan"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func benchmarkNativeScanner(logger *zap.Logger, stderr io.Writer, verbose bool) benchmark.NativeScanFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return func(ctx context.Context, req benchmark.NativeScanRequest) (benchmark.NativeScanResult, error) {
		// Build the native registry directly so local config and managed plugins
		// cannot change benchmark detector selection.
		detectorFilter := sdk.DetectorFilter{Exclude: []string{detectors.NameSyft}}
		ecosystemFilter := sdk.EcosystemFilter{Include: []sdk.Ecosystem{req.Ecosystem}}
		registry := engine.NewRegistry(engine.RegistryConfigs{}, *logger)
		registry.Build()
		filteredRegistry := registry.Filter(engine.RegistryFilter{
			DetectorFilter:  detectorFilter,
			EcosystemFilter: ecosystemFilter,
		})
		executionTarget := sdk.ExecutionTarget{
			Kind:          sdk.ExecutionTargetGitRepository,
			Location:      req.CheckoutDir,
			RepositoryURL: req.Repository,
			Ref:           req.Revision,
		}
		subprojects, err := opts.PlanSubprojects(filteredRegistry, opts.Request{
			Registry:        registry,
			ExecutionTarget: executionTarget,
			DetectorFilter:  detectorFilter,
			EcosystemFilter: ecosystemFilter,
		})
		if err != nil {
			return benchmark.NativeScanResult{}, fmt.Errorf("plan benchmark subprojects: %w", err)
		}
		logger.Debug("benchmark: native scan prepared",
			zap.String("repository", req.Repository),
			zap.String("revision", req.Revision),
			zap.String("ecosystem", string(req.Ecosystem)),
			zap.Int("subprojects", len(subprojects)),
		)
		result, err := scanengine.Run(ctx, engine.NewPipeline(filteredRegistry, logger), engine.PipelineRequest{
			ProjectPath:     req.CheckoutDir,
			ExecutionTarget: executionTarget,
			Subprojects:     subprojects,
			ScopeFilter:     sdk.ScopeUnknown,
			DetectorFilter:  detectorFilter,
			InstallFirst:    req.InstallFirst,
			Stderr:          stderr,
			Verbose:         verbose,
		})
		if err != nil {
			return benchmark.NativeScanResult{}, fmt.Errorf("run benchmark native scan: %w", err)
		}
		if result.Graph == nil {
			return benchmark.NativeScanResult{}, fmt.Errorf("run benchmark native scan: no graph resolved")
		}
		return benchmark.NativeScanResult{Graph: result.Graph, Detectors: benchmarkDetectorNames(result.ResolveResults)}, nil
	}
}

func benchmarkDetectorNames(results []sdk.DetectionResult) []string {
	seen := make(map[string]struct{}, len(results))
	names := make([]string, 0, len(results))
	for _, result := range results {
		name := strings.TrimSpace(result.DetectorName)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
