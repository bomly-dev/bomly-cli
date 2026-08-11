package node

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// Strategy action names accepted by StrategyConfig.Strategy.
const (
	// StrategyLockfile parses the committed lockfile directly, without
	// running the package manager.
	StrategyLockfile = "lockfile"
	// StrategyBuildTool resolves the graph by invoking the package manager
	// CLI.
	StrategyBuildTool = "buildtool"
)

// StrategyConfig is the standard configuration block shared by the merged
// Node detectors (npm, pnpm, yarn). It is decoded from the kind-scoped
// plugins.detectors.<name> block.
type StrategyConfig struct {
	// Strategy reorders or subsets the internal detection actions. Valid
	// values: "lockfile", "buildtool". Empty means the default
	// lockfile-first order.
	Strategy []string `json:"strategy" doc:"Ordered detection actions to run (subset or reordering of: lockfile, buildtool). Empty means lockfile first, then buildtool."`
	// InstallFirst gates install-first preparation for this detector. The
	// global --install-first flag still has to be passed for installs to
	// happen at all; setting this to false opts this detector out even then.
	InstallFirst *bool `json:"installFirst" doc:"Allow install-first preparation for this detector when install-first execution is requested." default:"true"`
}

// InstallFirstEnabled reports whether install-first preparation is allowed
// for this detector (default true).
func (c StrategyConfig) InstallFirstEnabled() bool {
	return c.InstallFirst == nil || *c.InstallFirst
}

// ResolveStrategyOrder validates and normalizes the configured action order.
// An empty configuration yields the default lockfile-first order.
func ResolveStrategyOrder(c StrategyConfig) ([]string, error) {
	if len(c.Strategy) == 0 {
		return []string{StrategyLockfile, StrategyBuildTool}, nil
	}
	order := make([]string, 0, len(c.Strategy))
	seen := make(map[string]struct{}, len(c.Strategy))
	for _, raw := range c.Strategy {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case StrategyLockfile, StrategyBuildTool:
		default:
			return nil, fmt.Errorf("unknown strategy action %q (valid actions: %s, %s)", raw, StrategyLockfile, StrategyBuildTool)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate strategy action %q", name)
		}
		seen[name] = struct{}{}
		order = append(order, name)
	}
	return order, nil
}

// Strategy pairs one internal detection action with the detector that
// implements it and the technique its results should be labelled with.
type Strategy struct {
	Name      string
	Detector  sdk.Detector
	Technique sdk.DetectorTechnique
}

// StrategiesReady reports readiness for a merged detector: ready when any
// configured strategy is ready, otherwise the joined per-strategy reasons.
func StrategiesReady(ctx context.Context, req sdk.DetectionRequest, strategies []Strategy) error {
	var errs []error
	for _, strategy := range strategies {
		err := strategy.Detector.Ready(ctx, req)
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s strategy: %w", strategy.Name, err))
	}
	if len(errs) == 0 {
		return errors.New("no detection strategies configured")
	}
	return errors.Join(errs...)
}

// StrategiesApplicable reports whether any configured strategy applies to the
// request.
func StrategiesApplicable(ctx context.Context, req sdk.DetectionRequest, strategies []Strategy) (bool, error) {
	var errs []error
	for _, strategy := range strategies {
		applicable, err := strategy.Detector.Applicable(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s strategy: %w", strategy.Name, err))
			continue
		}
		if applicable {
			return true, nil
		}
	}
	if len(errs) > 0 {
		return false, errors.Join(errs...)
	}
	return false, nil
}

// RunStrategies executes the configured actions in order with the historical
// chain semantics: a strategy that is not ready or fails records its error
// and hands off to the next one; a strategy that is not applicable hands off
// silently; the first strategy that produces a non-empty graph wins and its
// technique is stamped on the result. When every strategy fails the joined
// errors are returned.
func RunStrategies(ctx context.Context, req sdk.DetectionRequest, detectorName string, strategies []Strategy, logger *zap.Logger) (sdk.DetectionResult, error) {
	logger = req.DetectorLogger(logger)
	var errs []error
	for _, strategy := range strategies {
		if err := strategy.Detector.Ready(ctx, req); err != nil {
			logger.Debug("detector strategy not ready",
				zap.String("detector", detectorName),
				zap.String("strategy", strategy.Name),
				zap.Error(err),
			)
			errs = append(errs, fmt.Errorf("%s strategy not ready: %w", strategy.Name, err))
			continue
		}
		applicable, err := strategy.Detector.Applicable(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s strategy applicability check failed: %w", strategy.Name, err))
			continue
		}
		if !applicable {
			logger.Debug("detector strategy not applicable",
				zap.String("detector", detectorName),
				zap.String("strategy", strategy.Name),
			)
			continue
		}
		result, err := strategy.Detector.ResolveGraph(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s strategy: %w", strategy.Name, err))
			continue
		}
		if result.Graphs == nil || result.Graphs.Len() == 0 {
			errs = append(errs, fmt.Errorf("%s strategy: no graph data", strategy.Name))
			continue
		}
		result.Technique = strategy.Technique
		if len(errs) > 0 {
			logger.Info("detector strategy fell back",
				zap.String("detector", detectorName),
				zap.String("strategy", strategy.Name),
				zap.String("reason", errors.Join(errs...).Error()),
			)
		}
		return result, nil
	}
	if len(errs) == 0 {
		return sdk.DetectionResult{}, fmt.Errorf("no applicable detection strategy")
	}
	return sdk.DetectionResult{}, errors.Join(errs...)
}
