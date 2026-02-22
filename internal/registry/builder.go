package registry

import (
	"fmt"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/auditors/grype"
	osvauditor "github.com/bomly/bomly-cli/internal/auditors/osv"
	"github.com/bomly/bomly-cli/internal/detectors/composer"
	"github.com/bomly/bomly-cli/internal/detectors/githubactions"
	"github.com/bomly/bomly-cli/internal/detectors/gomod"
	"github.com/bomly/bomly-cli/internal/detectors/gradle"
	"github.com/bomly/bomly-cli/internal/detectors/maven"
	"github.com/bomly/bomly-cli/internal/detectors/node"
	"github.com/bomly/bomly-cli/internal/detectors/python"
	"github.com/bomly/bomly-cli/internal/detectors/ruby"
	sbomdetector "github.com/bomly/bomly-cli/internal/detectors/sbom"
	"github.com/bomly/bomly-cli/internal/detectors/syft"
	"github.com/bomly/bomly-cli/internal/licenses/clearlydefined"
	depsdevlicenses "github.com/bomly/bomly-cli/internal/licenses/depsdev"
	"github.com/bomly/bomly-cli/internal/plugin"
	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

// Config holds built-in registry wiring options resolved by the CLI layer.
type Config struct {
	HTTPProxy   string
	OsvAPIBase  string
	OsvCacheDir string
	OsvCacheTTL string
	KEVCacheDir string
	KEVCacheTTL string
}

// BuildScanRegistry creates the built-in scan registry, including plugins, auditors,
// matchers, and detectors derived from package-manager support metadata order.
func BuildScanRegistry(logger *zap.Logger, cfg Config) *scan.Registry {
	if logger == nil {
		logger = zap.NewNop()
	}

	builtins := scan.NewRegistry()
	discoverOpts := plugin.DiscoverOptions{}

	registerPluginStages(builtins, logger, discoverOpts)
	registerAuditors(builtins, logger, cfg)
	registerMatchers(builtins, logger, cfg)
	registerDetectors(builtins, orderedBuiltInDetectors(logger))
	registerBuiltInDiscoveryPlans(builtins)

	return builtins
}

func registerAuditors(builtins *scan.Registry, logger *zap.Logger, cfg Config) {
	osvCfg := osvauditor.DefaultConfig()
	osvCfg.Logger = logger
	if cfg.HTTPProxy != "" {
		osvCfg.ProxyURL = cfg.HTTPProxy
	}
	if cfg.OsvAPIBase != "" {
		osvCfg.APIBase = cfg.OsvAPIBase
	}
	if cfg.OsvCacheDir != "" {
		osvCfg.CacheDir = cfg.OsvCacheDir
	}
	if cfg.OsvCacheTTL != "" {
		if d, err := time.ParseDuration(cfg.OsvCacheTTL); err == nil {
			osvCfg.CacheTTL = d
		} else {
			logger.Warn("osv: invalid cache_ttl; using default", zap.String("value", cfg.OsvCacheTTL), zap.Error(err))
		}
	}
	if cfg.KEVCacheDir != "" {
		osvCfg.KEVCacheDir = cfg.KEVCacheDir
	}
	if cfg.KEVCacheTTL != "" {
		if d, err := time.ParseDuration(cfg.KEVCacheTTL); err == nil {
			osvCfg.KEVCacheTTL = d
		} else {
			logger.Warn("osv: invalid kev_cache_ttl; using default", zap.String("value", cfg.KEVCacheTTL), zap.Error(err))
		}
	}

	osvAud, err := osvauditor.New(osvCfg)
	if err != nil {
		logger.Warn("osv auditor unavailable", zap.Error(err))
	} else {
		builtins.RegisterAuditor(osvAud)
	}
	builtins.RegisterAuditor(grype.Auditor{Priority: 90, Logger: logger})
}

func registerMatchers(builtins *scan.Registry, logger *zap.Logger, cfg Config) {
	depsdevCfg := depsdevlicenses.DefaultConfig()
	depsdevCfg.Logger = logger
	if cfg.HTTPProxy != "" {
		depsdevCfg.ProxyURL = cfg.HTTPProxy
	}
	depsdevChecker, err := depsdevlicenses.New(depsdevCfg)
	if err != nil {
		logger.Warn("deps.dev license checker unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(depsdevChecker)
	}

	clearlyDefinedCfg := clearlydefined.DefaultConfig()
	clearlyDefinedCfg.Logger = logger
	if cfg.HTTPProxy != "" {
		clearlyDefinedCfg.ProxyURL = cfg.HTTPProxy
	}
	clearlyDefinedChecker, err := clearlydefined.New(clearlyDefinedCfg)
	if err != nil {
		logger.Warn("clearlydefined license checker unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(clearlyDefinedChecker)
	}
}

func registerDetectors(builtins *scan.Registry, detectors []scan.Detector) {
	for _, detector := range detectors {
		builtins.RegisterDetector(detector)
	}
}

func registerBuiltInDiscoveryPlans(builtins *scan.Registry) {
	builtins.RegisterDetectorDiscoveryPlan("syft-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: scan.SupportedEcosystemsForDetector("syft-detector"),
		SupportedManagers:   scan.SupportedPackageManagersForDetector("syft-detector"),
		TargetKinds:         []scan.ExecutionTargetKind{scan.ExecutionTargetContainerImage},
	})
}

func orderedBuiltInDetectors(logger *zap.Logger) []scan.Detector {
	detectorsByName := builtInDetectorsByName(logger)
	ordered := make([]scan.Detector, 0, len(detectorsByName))
	seen := make(map[string]struct{}, len(detectorsByName))

	for _, manager := range SupportedPackageManagers() {
		for _, detectorName := range manager.Detectors() {
			if detectorName == "" {
				continue
			}
			if _, ok := seen[detectorName]; ok {
				continue
			}
			detector, ok := detectorsByName[detectorName]
			if !ok || detector == nil {
				continue
			}
			seen[detectorName] = struct{}{}
			ordered = append(ordered, detector)
		}
	}

	return ordered
}

func builtInDetectorsByName(logger *zap.Logger) map[string]scan.Detector {
	syftFallback := syft.Detector{Logger: logger}
	syftPrimary := syft.Detector{
		Logger:              logger,
		SupportedManagers:   PreferredPackageManagersForDetector("syft-detector"),
		SupportedEcosystems: PreferredEcosystemsForDetector("syft-detector"),
	}
	sbomDetector := sbomdetector.Detector{Logger: logger}
	npmDetector := node.NPMDetector{Logger: logger, Fallback: syftFallback}
	pnpmDetector := node.PNPMDetector{Logger: logger, Fallback: syftFallback}
	yarnDetector := node.YarnDetector{Logger: logger, Fallback: syftFallback}
	gradleDetector := gradle.Detector{Logger: logger, Fallback: syftFallback}
	mavenDetector := maven.Detector{Logger: logger, Fallback: syftFallback}
	goDetector := gomod.Detector{Logger: logger, Fallback: syftFallback}
	composerDetector := composer.Detector{Logger: logger, Fallback: syftFallback}
	bundlerDetector := ruby.Detector{Logger: logger, Fallback: syftFallback}
	githubActionsDetector := githubactions.Detector{}
	pipDetector := python.PipDetector{Logger: logger, Fallback: syftFallback}
	pipenvDetector := python.PipenvDetector{Logger: logger, Fallback: syftFallback}
	poetryDetector := python.PoetryDetector{Logger: logger, Fallback: syftFallback}
	uvDetector := python.UVDetector{Logger: logger, Fallback: syftFallback}

	return map[string]scan.Detector{
		sbomDetector.Descriptor().Name:          sbomDetector,
		npmDetector.Descriptor().Name:           npmDetector,
		pnpmDetector.Descriptor().Name:          pnpmDetector,
		yarnDetector.Descriptor().Name:          yarnDetector,
		gradleDetector.Descriptor().Name:        gradleDetector,
		mavenDetector.Descriptor().Name:         mavenDetector,
		goDetector.Descriptor().Name:            goDetector,
		composerDetector.Descriptor().Name:      composerDetector,
		bundlerDetector.Descriptor().Name:       bundlerDetector,
		githubActionsDetector.Descriptor().Name: githubActionsDetector,
		pipDetector.Descriptor().Name:           pipDetector,
		pipenvDetector.Descriptor().Name:        pipenvDetector,
		poetryDetector.Descriptor().Name:        poetryDetector,
		uvDetector.Descriptor().Name:            uvDetector,
		syftPrimary.Descriptor().Name:           syftPrimary,
	}
}

// registerPluginStages inspects a discovered plugin's commands and registers
// the appropriate adapter for each pipeline stage it supports.
func registerPluginStages(builtins *scan.Registry, logger *zap.Logger, discoverOpts plugin.DiscoverOptions) {
	plugins, discoverErr := plugin.Discover(discoverOpts)
	if discoverErr != nil {
		logger.Warn("plugin discovery failed", zap.Error(discoverErr))
	}
	for _, p := range plugins {
		for _, cmd := range p.Metadata.Commands {
			stage := cmd.EffectiveStage()
			switch stage {
			case plugin.StageDetect:
				logger.Debug("registering plugin detector", zap.String("plugin", p.Metadata.Name), zap.String("command", cmd.Name))
				detectorName := pluginDetectorName(p.Metadata.Name, cmd.Name)
				supportedEcosystems := parsePluginEcosystems(logger, p.Metadata.Name, cmd)
				supportedManagers := parsePluginPackageManagers(logger, p.Metadata.Name, cmd)
				builtins.RegisterDetector(plugin.Detector{
					PluginName:          p.Metadata.Name,
					DetectorName:        detectorName,
					Subcommand:          cmd.Name,
					SupportedEcosystems: supportedEcosystems,
					PackageManagers:     supportedManagers,
					DiscoverOptions:     discoverOpts,
				})
				if plan, ok := pluginDiscoveryPlan(logger, p.Metadata.Name, cmd, supportedEcosystems, supportedManagers); ok {
					builtins.RegisterDetectorDiscoveryPlan(detectorName, plan)
				}
			case plugin.StagePreResolve:
				logger.Debug("registering plugin pre-resolve hook", zap.String("plugin", p.Metadata.Name), zap.String("command", cmd.Name))
				builtins.RegisterPreResolveHook(plugin.PreResolveHook{
					PluginPath: p.Path,
					PluginName: p.Metadata.Name,
					Subcommand: cmd.Name,
					Priority:   100,
				})
			case plugin.StageAudit:
				logger.Debug("registering plugin auditor", zap.String("plugin", p.Metadata.Name), zap.String("command", cmd.Name))
				builtins.RegisterAuditor(plugin.Auditor{
					PluginPath: p.Path,
					PluginName: p.Metadata.Name,
					Subcommand: cmd.Name,
				})
			case plugin.StagePostResolve:
				logger.Debug("registering plugin post-resolve hook", zap.String("plugin", p.Metadata.Name), zap.String("command", cmd.Name))
				builtins.RegisterPostResolveHook(plugin.PostResolveHook{
					PluginPath: p.Path,
					PluginName: p.Metadata.Name,
					Subcommand: cmd.Name,
					Priority:   100,
				})
			default:
				logger.Warn("plugin command with unknown stage", zap.String("plugin", p.Metadata.Name), zap.String("stage", stage))
			}
		}
	}
}

func pluginDetectorName(pluginName, commandName string) string {
	base := strings.ToLower(strings.TrimSpace(pluginName))
	command := strings.ToLower(strings.TrimSpace(commandName))
	if command == "" || command == "detect" {
		return base + "-plugin-detector"
	}
	command = strings.ReplaceAll(command, " ", "-")
	command = strings.ReplaceAll(command, "/", "-")
	return base + "-" + command + "-plugin-detector"
}

func parsePluginEcosystems(logger *zap.Logger, pluginName string, cmd plugin.Command) []scan.Ecosystem {
	if len(cmd.Ecosystems) == 0 {
		return nil
	}
	values := make([]scan.Ecosystem, 0, len(cmd.Ecosystems))
	seen := make(map[scan.Ecosystem]struct{}, len(cmd.Ecosystems))
	for _, raw := range cmd.Ecosystems {
		ecosystem, err := scan.ParseEcosystem(raw)
		if err != nil {
			logger.Warn("plugin detector has invalid ecosystem metadata", zap.String("plugin", pluginName), zap.String("value", raw), zap.Error(err))
			continue
		}
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		values = append(values, ecosystem)
	}
	return values
}

func parsePluginPackageManagers(logger *zap.Logger, pluginName string, cmd plugin.Command) []scan.PackageManager {
	if len(cmd.PackageManagers) == 0 {
		return nil
	}
	values := make([]scan.PackageManager, 0, len(cmd.PackageManagers))
	seen := make(map[scan.PackageManager]struct{}, len(cmd.PackageManagers))
	for _, raw := range cmd.PackageManagers {
		manager, err := scan.ParsePackageManager(raw)
		if err != nil {
			logger.Warn("plugin detector has invalid package-manager metadata", zap.String("plugin", pluginName), zap.String("value", raw), zap.Error(err))
			continue
		}
		if _, ok := seen[manager]; ok {
			continue
		}
		seen[manager] = struct{}{}
		values = append(values, manager)
	}
	return values
}

func pluginDiscoveryPlan(
	logger *zap.Logger,
	pluginName string,
	cmd plugin.Command,
	supportedEcosystems []scan.Ecosystem,
	supportedManagers []scan.PackageManager,
) (scan.DetectorDiscoveryPlan, bool) {
	if len(cmd.EvidencePatterns) == 0 && len(cmd.TargetKinds) == 0 {
		return scan.DetectorDiscoveryPlan{}, false
	}

	targetKinds := parsePluginTargetKinds(logger, pluginName, cmd)
	if len(targetKinds) == 0 && len(cmd.EvidencePatterns) > 0 {
		targetKinds = []scan.ExecutionTargetKind{scan.ExecutionTargetFilesystem, scan.ExecutionTargetGitRepository}
	}
	if len(targetKinds) == 0 {
		return scan.DetectorDiscoveryPlan{}, false
	}

	plan := scan.DetectorDiscoveryPlan{
		SupportedEcosystems: append([]scan.Ecosystem(nil), supportedEcosystems...),
		SupportedManagers:   append([]scan.PackageManager(nil), supportedManagers...),
		EvidencePatterns:    append([]string(nil), cmd.EvidencePatterns...),
		TargetKinds:         targetKinds,
	}
	return plan, true
}

func parsePluginTargetKinds(logger *zap.Logger, pluginName string, cmd plugin.Command) []scan.ExecutionTargetKind {
	if len(cmd.TargetKinds) == 0 {
		return nil
	}
	values := make([]scan.ExecutionTargetKind, 0, len(cmd.TargetKinds))
	seen := make(map[scan.ExecutionTargetKind]struct{}, len(cmd.TargetKinds))
	for _, raw := range cmd.TargetKinds {
		targetKind, err := parsePluginTargetKind(raw)
		if err != nil {
			logger.Warn("plugin detector has invalid target-kind metadata", zap.String("plugin", pluginName), zap.String("value", raw), zap.Error(err))
			continue
		}
		if _, ok := seen[targetKind]; ok {
			continue
		}
		seen[targetKind] = struct{}{}
		values = append(values, targetKind)
	}
	return values
}

func parsePluginTargetKind(value string) (scan.ExecutionTargetKind, error) {
	switch scan.ExecutionTargetKind(strings.TrimSpace(value)) {
	case scan.ExecutionTargetFilesystem:
		return scan.ExecutionTargetFilesystem, nil
	case scan.ExecutionTargetGitRepository:
		return scan.ExecutionTargetGitRepository, nil
	case scan.ExecutionTargetContainerImage:
		return scan.ExecutionTargetContainerImage, nil
	default:
		return "", fmt.Errorf("unsupported target kind %q", value)
	}
}
