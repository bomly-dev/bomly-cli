package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// resolveAll resolves dependency graphs for each subproject using registered detectors.
func (p *Pipeline) resolveAll(ctx context.Context, req PipelineRequest) ([]sdk.DetectionResult, error) {
	type subprojectResolution struct {
		results []sdk.DetectionResult
		err     error
	}
	ordered := make([]subprojectResolution, len(req.Subprojects))

	if p.Logger.Core().Enabled(zap.DebugLevel) {
		for _, sub := range req.Subprojects {
			p.Logger.Debug("pipeline: subproject queued",
				zap.String("path", sub.RelativePath),
				zap.String("package_manager", sub.PrimaryPackageManager().Name()),
				zap.String("primary_detector", sub.PrimaryDetector),
				zap.String("ecosystem", string(sub.Ecosystem)),
				zap.Strings("planned_detectors", sub.PlannedDetectors),
			)
		}
	}

	workerCount := resolveWorkerCount(len(req.Subprojects))
	if req.Progress != nil {
		req.Progress.StartStage("Detecting dependencies", len(req.Subprojects))
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	completed := 0
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				sub := req.Subprojects[idx]
				reportProgressDetail(req.Progress, "Detecting dependencies", subprojectProgressDetail(sub))
				subResults, err := p.resolveSubproject(ctx, req, sub)
				ordered[idx] = subprojectResolution{results: subResults, err: err}
				if req.Progress != nil {
					progressMu.Lock()
					completed++
					req.Progress.AdvanceStage("Detecting dependencies", completed, len(req.Subprojects))
					progressMu.Unlock()
				}
			}
		}()
	}
	for idx := range req.Subprojects {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
	if req.Progress != nil {
		req.Progress.CompleteStage("Detecting dependencies", len(req.Subprojects))
	}

	results := make([]sdk.DetectionResult, 0, len(req.Subprojects))
	var errs []error
	for idx, resolution := range ordered {
		sub := req.Subprojects[idx]
		if resolution.err != nil {
			errs = append(errs, fmt.Errorf("subproject %s (%s/%s): %w", sub.RelativePath, sub.Ecosystem, sub.PrimaryPackageManager(), resolution.err))
			continue
		}
		results = append(results, resolution.results...)
	}

	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}
	return results, nil
}

func resolveWorkerCount(subprojectCount int) int {
	if subprojectCount <= 1 {
		return 1
	}
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}
	if workers > subprojectCount {
		return subprojectCount
	}
	return workers
}

func (p *Pipeline) resolveSubproject(ctx context.Context, req PipelineRequest, sub sdk.Subproject) ([]sdk.DetectionResult, error) {
	baseReq := sdk.DetectionRequest{
		ProjectPath:       sub.ExecutionTarget.Location,
		ExecutionTarget:   sub.ExecutionTarget,
		Subproject:        sub,
		Ecosystem:         sub.Ecosystem,
		PackageManager:    sub.PrimaryPackageManager(),
		EnrichmentEnabled: req.EnrichEnabled || req.MatchEnabled,
		DetectorFilter:    req.DetectorFilter,
		ScopeFilter:       req.ScopeFilter,
		InstallFirst:      req.InstallFirst,
		InstallArgs:       req.InstallArgs,
		CoreVersion:       req.CoreVersion,
		Stderr:            req.Stderr,
		Verbose:           req.Verbose,
	}

	detectorNames := sub.PlannedDetectors
	detectorList := p.Registry.PlannedDetectors(baseReq, detectorNames)
	if len(detectorList) == 0 {
		p.Logger.Warn("pipeline: no detector registered for subproject",
			zap.String("path", sub.RelativePath),
			zap.String("ecosystem", string(sub.Ecosystem)),
			zap.String("package_manager", sub.PrimaryPackageManager().Name()),
			zap.Strings("planned_detectors", detectorNames),
		)
		return nil, fmt.Errorf("no detector registered for ecosystem %q and package manager %q", sub.Ecosystem, sub.PrimaryPackageManager())
	}

	results, err := p.resolveDetectors(ctx, baseReq, detectorList[:1], req.Progress)
	if err != nil {
		return nil, err
	}
	for idx := range results {
		results[idx].RootExecutionTarget = req.ExecutionTarget
	}
	return results, nil
}

// resolveDetectors runs matched detectors in priority order. Detectors may
// provide their own fallback detector when they cannot produce a result.
func (p *Pipeline) resolveDetectors(ctx context.Context, req sdk.DetectionRequest, detectorList []sdk.Detector, progress ProgressReporter) ([]sdk.DetectionResult, error) {
	var results []sdk.DetectionResult
	var errs []error
	succeeded := make(map[string]struct{}, len(detectorList))

	for _, detector := range detectorList {
		descriptor := detector.Descriptor()
		if _, ok := succeeded[descriptor.Name]; ok {
			continue
		}
		detectorResults, err := p.resolveDetector(ctx, req, detector, progress)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, detectorResults...)
		for _, result := range detectorResults {
			if result.DetectorName != "" {
				succeeded[result.DetectorName] = struct{}{}
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.Join(errs...)
	}
	return results, nil
}

func (p *Pipeline) resolveDetector(ctx context.Context, req sdk.DetectionRequest, detector sdk.Detector, progress ProgressReporter) ([]sdk.DetectionResult, error) {
	descriptor := detector.Descriptor()
	support := detector.PackageManagerSupport()
	reportProgressDetail(progress, "Detecting dependencies", detectorProgressDetail(req.Subproject, descriptor.Label()))
	p.Logger.Debug("pipeline: detector starting",
		zap.String("detector", descriptor.Name),
		zap.String("subproject", req.Subproject.RelativePath),
		zap.String("ecosystem", string(req.Ecosystem)),
		zap.String("package_manager", req.PackageManager.Name()),
		zap.Strings("evidence_patterns", evidencePatternsForSupport(support, req.PackageManager)),
		zap.Bool("install_first_requested", req.InstallFirst),
		zap.Bool("install_first_supported", descriptor.SupportsInstallFirst),
	)

	if !detector.Ready() {
		p.Logger.Debug("pipeline: detector not ready",
			zap.String("detector", descriptor.Name),
			zap.String("subproject", req.Subproject.RelativePath),
		)
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: not ready", descriptor.Name), progress)
	}

	applicable, err := detector.Applicable(ctx, req)
	if err != nil {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: applicability check failed: %w", descriptor.Name, err), progress)
	}
	if !applicable {
		p.Logger.Debug("pipeline: detector not applicable",
			zap.String("detector", descriptor.Name),
			zap.String("subproject", req.Subproject.RelativePath),
		)
		return p.resolveFallback(ctx, req, detector, nil, progress)
	}

	if req.InstallFirst {
		if installer, ok := detector.(sdk.InstallFirstDetector); ok {
			p.Logger.Debug("pipeline: running detector install-first",
				zap.String("detector", descriptor.Name),
				zap.String("subproject", req.Subproject.RelativePath),
				zap.Strings("install_args", req.InstallArgs),
			)
			if err := installer.Install(ctx, req); err != nil {
				return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: install-first failed: %w", descriptor.Name, err), progress)
			}
		} else {
			p.Logger.Debug("pipeline: detector does not support install-first",
				zap.String("detector", descriptor.Name),
				zap.String("subproject", req.Subproject.RelativePath),
			)
		}
	} else if descriptor.SupportsInstallFirst {
		p.Logger.Debug("pipeline: detector supports install-first",
			zap.String("detector", descriptor.Name),
			zap.String("subproject", req.Subproject.RelativePath),
			zap.String("hint", "use --install-first when dependencies must be installed before graph resolution"),
		)
	}

	result, err := detector.ResolveGraph(ctx, req)
	if err != nil {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: %w", descriptor.Name, err), progress)
	}
	if result.Graphs == nil || result.Graphs.Len() == 0 {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: no graph data", descriptor.Name), progress)
	}
	result, err = sdk.FilterDetectionResultByScope(result, req.ScopeFilter)
	if err != nil {
		return p.resolveFallback(ctx, req, detector, fmt.Errorf("detector %s: scope filter: %w", descriptor.Name, err), progress)
	}

	result.SubprojectInfo = req.Subproject
	result.DetectorName = descriptor.Name
	result.Origin = p.Registry.DetectorOrigin(descriptor.Name)
	result.Technique = descriptor.Technique
	packages, edges := graphContainerStats(result.Graphs)
	p.Logger.Debug("pipeline: detector succeeded",
		zap.String("detector", descriptor.Name),
		zap.String("subproject", req.Subproject.RelativePath),
		zap.Int("graphs", result.Graphs.Len()),
		zap.Int("packages", packages),
		zap.Int("edges", edges),
	)
	return []sdk.DetectionResult{result}, nil
}

func (p *Pipeline) resolveFallback(ctx context.Context, req sdk.DetectionRequest, detector sdk.Detector, primaryErr error, progress ProgressReporter) ([]sdk.DetectionResult, error) {
	fallbackProvider, ok := detector.(sdk.FallbackDetector)
	if !ok {
		return nil, primaryErr
	}
	fallback := fallbackProvider.FallbackDetector()
	if fallback == nil {
		return nil, primaryErr
	}
	if !fallbackSelected(req.DetectorFilter, fallback.Descriptor()) {
		p.Logger.Debug("pipeline: fallback detector skipped by filter",
			zap.String("detector", detector.Descriptor().Name),
			zap.String("fallback_detector", fallback.Descriptor().Name),
			zap.String("subproject", req.Subproject.RelativePath),
		)
		return nil, primaryErr
	}
	p.Logger.Debug("pipeline: trying fallback detector",
		zap.String("detector", detector.Descriptor().Name),
		zap.String("fallback_detector", fallback.Descriptor().Name),
		zap.String("subproject", req.Subproject.RelativePath),
		zap.Error(primaryErr),
	)
	results, fallbackErr := p.resolveDetector(ctx, req, fallback, progress)
	if primaryErr == nil {
		return results, fallbackErr
	}
	if fallbackErr == nil {
		return results, nil
	}
	return nil, errors.Join(primaryErr, fallbackErr)
}

func reportProgressDetail(progress ProgressReporter, label, detail string) {
	if reporter, ok := progress.(DetailProgressReporter); ok {
		reporter.Detail(label, detail)
	}
}

func subprojectProgressDetail(sub sdk.Subproject) string {
	label := strings.TrimSpace(sub.RelativePath)
	if label == "" || label == "." {
		label = filepath.Base(sub.ExecutionTarget.Location)
	}
	if label == "" || label == "." {
		label = "root"
	}
	manager := sub.PrimaryPackageManager().Name()
	if manager == "" {
		return label
	}
	return fmt.Sprintf("%s (%s)", label, manager)
}

func detectorProgressDetail(sub sdk.Subproject, detectorName string) string {
	detail := subprojectProgressDetail(sub)
	if detectorName == "" {
		return detail
	}
	return detectorName + " - " + detail
}

func evidencePatternsForSupport(support []sdk.PackageManagerSupport, manager sdk.PackageManager) []string {
	var values []string
	for _, entry := range support {
		if manager != sdk.PackageManagerUnknown && entry.PackageManager != manager {
			continue
		}
		values = append(values, entry.EvidencePatterns...)
	}
	if len(values) == 0 {
		for _, entry := range support {
			values = append(values, entry.EvidencePatterns...)
		}
	}
	return dedupeStrings(values)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func graphContainerStats(container *sdk.GraphContainer) (packages, edges int) {
	if container == nil {
		return 0, 0
	}
	for _, entry := range container.Entries {
		if entry.Graph == nil {
			continue
		}
		packages += entry.Graph.Size()
		entry.Graph.WalkEdges(func(_, _ *sdk.Dependency) bool {
			edges++
			return true
		})
	}
	return packages, edges
}

func fallbackSelected(filter sdk.DetectorFilter, descriptor sdk.DetectorDescriptor) bool {
	if descriptor.Name == "" {
		return false
	}
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 && !filter.Includes(descriptor.Name) {
		return false
	}
	return true
}
