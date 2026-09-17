package npm

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Detector is the merged npm detector. It owns an internal ordered strategy
// (lockfile parse first, npm CLI resolution as fallback) that used to be two
// separately registered detectors chained through Fallback fields.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Config     node.StrategyConfig
}

// Descriptor describes the merged npm detector.
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameNPM,
		RemediationCapabilities: npmLockfileRemediationCapabilities(),
		Technique:               plugin.MultipleTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:       []model.PackageManager{model.PackageManagerNPM},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst:    true,
		ConfigSchema:            plugin.MustConfigSchemaFor(node.StrategyConfig{}),
	}
}

// PackageManagerSupport returns npm package-manager discovery metadata for
// every internal strategy: lockfile evidence plus the manifest the CLI
// strategy can resolve from.
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	patterns := append(append([]string(nil), npmEvidencePatterns...), "package.json")
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, patterns...).WithMultiModule()}
}

func (d Detector) strategies() ([]node.Strategy, error) {
	order, err := node.ResolveStrategyOrder(d.Config)
	if err != nil {
		return nil, fmt.Errorf("npm detector configuration: %w", err)
	}
	strategies := make([]node.Strategy, 0, len(order))
	for _, name := range order {
		switch name {
		case node.StrategyLockfile:
			strategies = append(strategies, node.Strategy{
				Name:      name,
				Detector:  LockfileDetector{Logger: d.Logger, WorkingDir: d.WorkingDir},
				Technique: plugin.LockfileTechnique,
			})
		case node.StrategyBuildTool:
			strategies = append(strategies, node.Strategy{
				Name:      name,
				Detector:  NativeDetector{Logger: d.Logger, WorkingDir: d.WorkingDir},
				Technique: plugin.BuildToolTechnique,
			})
		}
	}
	return strategies, nil
}

// Ready reports whether any configured strategy can run.
func (d Detector) Ready(ctx context.Context, req plugin.DetectionRequest) error {
	strategies, err := d.strategies()
	if err != nil {
		return err
	}
	return node.StrategiesReady(ctx, req, strategies)
}

// Applicable reports whether any configured strategy applies to the request.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	strategies, err := d.strategies()
	if err != nil {
		return false, err
	}
	return node.StrategiesApplicable(ctx, req, strategies)
}

// ResolveGraph runs the configured strategies in order and returns the first
// successful graph.
func (d Detector) ResolveGraph(ctx context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	strategies, err := d.strategies()
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	return node.RunStrategies(ctx, req, detectors.NameNPM, strategies, d.Logger)
}

// Install prepares npm dependencies before graph resolution, unless the
// detector's configuration opted out of install-first execution.
func (d Detector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	if !d.Config.InstallFirstEnabled() {
		req.DetectorLogger(d.Logger).Info("npm detector: install-first disabled by configuration; skipping install")
		return nil
	}
	return NativeDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}.Install(ctx, req)
}

// RemediationHints provides npm-specific remediation guidance.
func (d Detector) RemediationHints(ctx context.Context, request plugin.RemediationHintRequest) (plugin.RemediationHintResponse, error) {
	return LockfileDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}.RemediationHints(ctx, request)
}
