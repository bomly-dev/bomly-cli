package yarn

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// Detector is the merged Yarn detector. It owns an internal ordered strategy
// (lockfile parse first, yarn CLI resolution as fallback) that used to be two
// separately registered detectors chained through Fallback fields.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Config     node.StrategyConfig
}

// Descriptor describes the merged Yarn detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:      []string{"node_modules", "dist"},
		Name:                    detectors.NameYarn,
		RemediationCapabilities: yarnLockfileRemediationCapabilities(),
		Technique:               sdk.MultipleTechnique,
		SupportedEcosystems:     []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:       []sdk.PackageManager{sdk.PackageManagerYarn},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "scope-annotation"},
		SupportsInstallFirst:    true,
		ConfigSchema:            sdk.MustConfigSchemaFor(node.StrategyConfig{}),
	}
}

// PackageManagerSupport returns Yarn package-manager discovery metadata for
// every internal strategy: lockfile evidence plus the manifest the CLI
// strategy can resolve from.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	patterns := append(append([]string(nil), yarnEvidencePatterns...), "package.json")
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerYarn, patterns...).WithMultiModule()}
}

func (d Detector) strategies() ([]node.Strategy, error) {
	order, err := node.ResolveStrategyOrder(d.Config)
	if err != nil {
		return nil, fmt.Errorf("yarn detector configuration: %w", err)
	}
	strategies := make([]node.Strategy, 0, len(order))
	for _, name := range order {
		switch name {
		case node.StrategyLockfile:
			strategies = append(strategies, node.Strategy{
				Name:      name,
				Detector:  LockfileDetector{Logger: d.Logger, WorkingDir: d.WorkingDir},
				Technique: sdk.LockfileTechnique,
			})
		case node.StrategyBuildTool:
			strategies = append(strategies, node.Strategy{
				Name:      name,
				Detector:  NativeDetector{Logger: d.Logger, WorkingDir: d.WorkingDir},
				Technique: sdk.BuildToolTechnique,
			})
		}
	}
	return strategies, nil
}

// Ready reports whether any configured strategy can run.
func (d Detector) Ready(ctx context.Context, req sdk.DetectionRequest) error {
	strategies, err := d.strategies()
	if err != nil {
		return err
	}
	return node.StrategiesReady(ctx, req, strategies)
}

// Applicable reports whether any configured strategy applies to the request.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	strategies, err := d.strategies()
	if err != nil {
		return false, err
	}
	return node.StrategiesApplicable(ctx, req, strategies)
}

// ResolveGraph runs the configured strategies in order and returns the first
// successful graph.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	strategies, err := d.strategies()
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return node.RunStrategies(ctx, req, detectors.NameYarn, strategies, d.Logger)
}

// Install prepares Yarn dependencies before graph resolution, unless the
// detector's configuration opted out of install-first execution.
func (d Detector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	if !d.Config.InstallFirstEnabled() {
		req.DetectorLogger(d.Logger).Info("yarn detector: install-first disabled by configuration; skipping install")
		return nil
	}
	return NativeDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}.Install(ctx, req)
}

// RemediationHints provides Yarn-specific remediation guidance.
func (d Detector) RemediationHints(ctx context.Context, request sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return LockfileDetector{Logger: d.Logger, WorkingDir: d.WorkingDir}.RemediationHints(ctx, request)
}
