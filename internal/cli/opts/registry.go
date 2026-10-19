package opts

import (
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"

	"github.com/bomly-dev/bomly-sdk/model"
)

// RegistryConfigsFromResolved converts resolved CLI configuration into scan registry wiring.
// Validation of FailOn values happens earlier in the CLI pipeline; here we
// drop parse errors and keep only the valid constraints so secondary
// callers (tests, plugin adapters) stay functional.
func RegistryConfigsFromResolved(cfg config.Resolved) engine.RegistryConfigs {
	failOn, _ := model.ParseFailOnList(cfg.FailOn)
	return engine.RegistryConfigs{
		FailOn:                     failOn,
		AllowVulnerabilityIDs:      append([]string(nil), cfg.AllowVulnerabilityIDs...),
		AllowLicenses:              append([]string(nil), cfg.AllowLicenses...),
		DenyLicenses:               append([]string(nil), cfg.DenyLicenses...),
		LicenseExemptPackages:      append([]string(nil), cfg.LicenseExemptPackages...),
		DenyPackages:               append([]string(nil), cfg.DenyPackages...),
		DenyGroups:                 append([]string(nil), cfg.DenyGroups...),
		ProtectedPackages:          append([]string(nil), cfg.ProtectedPackages...),
		TyposquatThreshold:         cfg.TyposquatThreshold,
		TyposquatMode:              cfg.TyposquatMode,
		OsvAPIBase:                 cfg.OsvAPIBase,
		OsvCacheDir:                cfg.OsvCacheDir,
		OsvCacheTTL:                cfg.OsvCacheTTL,
		KEVCacheDir:                cfg.KEVCacheDir,
		KEVCacheTTL:                cfg.KEVCacheTTL,
		ScorecardAPIBase:           cfg.ScorecardAPIBase,
		ScorecardCacheDir:          cfg.ScorecardCacheDir,
		ScorecardCacheTTL:          cfg.ScorecardCacheTTL,
		GrypeDBUpdateDisabled:      grypeDBUpdateDisabled(cfg.GrypeDBAutoUpdate),
		GrypeDBMaxAge:              cfg.GrypeDBMaxAge,
		GrypeDBUpdateCheckInterval: cfg.GrypeDBUpdateCheckInterval,
		HTTPProxy:                  cfg.HTTPProxy,
		HTTPNoProxy:                cfg.HTTPNoProxy,
		HTTPProxyType:              cfg.HTTPProxyType,
		HTTPProxyHost:              cfg.HTTPProxyHost,
		HTTPProxyPort:              cfg.HTTPProxyPort,
		HTTPProxyUsername:          cfg.HTTPProxyUsername,
		HTTPProxyPassword:          cfg.HTTPProxyPassword,
		HTTPCACertFile:             cfg.HTTPCACertFile,
		PluginConfigs:              cfg.Plugins,
		CoreVersion:                cfg.CoreVersion,
	}
}

// grypeDBUpdateDisabled turns the matchers.grype.db_auto_update setting into
// the matcher's switch, with the grammar config.Validate accepted ("off" and
// "no" disable it, not only "false"). An empty or malformed value, which
// Validate has already rejected on the CLI path, keeps the update on.
func grypeDBUpdateDisabled(autoUpdate string) bool {
	enabled, ok := config.ParseBool(autoUpdate)
	return ok && !enabled
}
