package registry

import (
	"time"

	"github.com/bomly/bomly-cli/internal/auditors/policy"
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
	"github.com/bomly/bomly-cli/internal/matchers/clearlydefined"
	"github.com/bomly/bomly-cli/internal/matchers/depsdev"
	"github.com/bomly/bomly-cli/internal/matchers/eol"
	"github.com/bomly/bomly-cli/internal/matchers/grype"
	osvmatcher "github.com/bomly/bomly-cli/internal/matchers/osv"
	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

// Config holds built-in registry wiring options resolved by the CLI layer.
type Config struct {
	FailOn      string
	OsvAPIBase  string
	OsvCacheDir string
	OsvCacheTTL string
	KEVCacheDir string
	KEVCacheTTL string
	EOLAPIBase  string
	EOLCacheDir string
	EOLCacheTTL string
}

// BuildScanRegistry creates the built-in scan registry, including auditors,
// matchers, and detectors derived from package-manager support metadata order.
func BuildScanRegistry(logger *zap.Logger, cfg Config) *scan.Registry {
	if logger == nil {
		logger = zap.NewNop()
	}

	builtins := scan.NewRegistry()
	registerAuditors(builtins, logger, cfg)
	registerMatchers(builtins, logger, cfg)
	registerDetectors(builtins, orderedBuiltInDetectors(logger))
	registerBuiltInDiscoveryPlans(builtins)

	return builtins
}

func registerAuditors(builtins *scan.Registry, logger *zap.Logger, cfg Config) {
	builtins.RegisterAuditor(policy.Auditor{FailOn: cfg.FailOn})
}

func registerMatchers(builtins *scan.Registry, logger *zap.Logger, cfg Config) {
	osvCfg := osvmatcher.DefaultConfig()
	osvCfg.Logger = logger
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

	osvMatcher, err := osvmatcher.New(osvCfg)
	if err != nil {
		logger.Warn("osv matcher unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(osvMatcher)
	}
	builtins.RegisterMatcher(grype.Matcher{Priority: 90, Logger: logger})

	eolCfg := eol.DefaultConfig()
	eolCfg.Logger = logger
	if cfg.EOLAPIBase != "" {
		eolCfg.APIBase = cfg.EOLAPIBase
	}
	if cfg.EOLCacheDir != "" {
		eolCfg.CacheDir = cfg.EOLCacheDir
	}
	if cfg.EOLCacheTTL != "" {
		if d, err := time.ParseDuration(cfg.EOLCacheTTL); err == nil {
			eolCfg.CacheTTL = d
		} else {
			logger.Warn("eol: invalid cache_ttl; using default", zap.String("value", cfg.EOLCacheTTL), zap.Error(err))
		}
	}
	eolChecker, err := eol.New(eolCfg)
	if err != nil {
		logger.Warn("endoflife.date checker unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(eolChecker)
		logger.Debug("endoflife.date matcher configured",
			zap.String("api_base", eolCfg.APIBase),
			zap.String("cache_dir", eolCfg.CacheDir),
			zap.Duration("cache_ttl", eolCfg.CacheTTL),
		)
	}

	depsdevCfg := depsdev.DefaultConfig()
	depsdevCfg.Logger = logger
	depsdevChecker, err := depsdev.New(depsdevCfg)
	if err != nil {
		logger.Warn("deps.dev license checker unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(depsdevChecker)
		logger.Debug("deps.dev matcher configured")
	}

	clearlyDefinedCfg := clearlydefined.DefaultConfig()
	clearlyDefinedCfg.Logger = logger
	clearlyDefinedChecker, err := clearlydefined.New(clearlyDefinedCfg)
	if err != nil {
		logger.Warn("clearlydefined license checker unavailable", zap.Error(err))
	} else {
		builtins.RegisterMatcher(clearlyDefinedChecker)
		logger.Debug("clearlydefined matcher configured")
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
