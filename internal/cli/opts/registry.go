package opts

import (
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// RegistryConfigsFromResolved converts resolved CLI configuration into scan registry wiring.
// Validation of FailOn values happens earlier in the CLI pipeline; here we
// drop parse errors and keep only the valid constraints so secondary
// callers (tests, plugin adapters) stay functional.
func RegistryConfigsFromResolved(cfg config.Resolved) engine.RegistryConfigs {
	failOn, _ := sdk.ParseFailOnList(cfg.FailOn)
	failOnScopes := make([]sdk.Scope, 0, len(cfg.FailOnScopes))
	for _, rawScope := range cfg.FailOnScopes {
		scope, err := sdk.ParseScope(rawScope)
		if err != nil {
			continue
		}
		failOnScopes = append(failOnScopes, scope)
	}
	return engine.RegistryConfigs{
		FailOn:                failOn,
		FailOnScopes:          failOnScopes,
		AllowVulnerabilityIDs: append([]string(nil), cfg.AllowVulnerabilityIDs...),
		AllowLicenses:         append([]string(nil), cfg.AllowLicenses...),
		DenyLicenses:          append([]string(nil), cfg.DenyLicenses...),
		LicenseExemptPackages: append([]string(nil), cfg.LicenseExemptPackages...),
		DenyPackages:          append([]string(nil), cfg.DenyPackages...),
		DenyGroups:            append([]string(nil), cfg.DenyGroups...),
		ProtectedPackages:     append([]string(nil), cfg.ProtectedPackages...),
		TyposquatThreshold:    cfg.TyposquatThreshold,
		TyposquatMode:         cfg.TyposquatMode,
		OsvAPIBase:            cfg.OsvAPIBase,
		OsvCacheDir:           cfg.OsvCacheDir,
		OsvCacheTTL:           cfg.OsvCacheTTL,
		KEVCacheDir:           cfg.KEVCacheDir,
		KEVCacheTTL:           cfg.KEVCacheTTL,
		ScorecardAPIBase:      cfg.ScorecardAPIBase,
		ScorecardCacheDir:     cfg.ScorecardCacheDir,
		ScorecardCacheTTL:     cfg.ScorecardCacheTTL,
		HTTPProxy:             cfg.HTTPProxy,
		HTTPNoProxy:           cfg.HTTPNoProxy,
		HTTPProxyType:         cfg.HTTPProxyType,
		HTTPProxyHost:         cfg.HTTPProxyHost,
		HTTPProxyPort:         cfg.HTTPProxyPort,
		HTTPProxyUsername:     cfg.HTTPProxyUsername,
		HTTPProxyPassword:     cfg.HTTPProxyPassword,
		HTTPCACertFile:        cfg.HTTPCACertFile,
	}
}
