package opts

import (
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
)

// RegistryConfigsFromResolved converts resolved CLI configuration into scan registry wiring.
func RegistryConfigsFromResolved(cfg config.Resolved) engine.RegistryConfigs {
	return engine.RegistryConfigs{
		FailOn:      cfg.FailOn,
		OsvAPIBase:  cfg.OsvAPIBase,
		OsvCacheDir: cfg.OsvCacheDir,
		OsvCacheTTL: cfg.OsvCacheTTL,
		KEVCacheDir: cfg.KEVCacheDir,
		KEVCacheTTL: cfg.KEVCacheTTL,
		EOLAPIBase:  cfg.EOLAPIBase,
		EOLCacheDir: cfg.EOLCacheDir,
		EOLCacheTTL: cfg.EOLCacheTTL,
	}
}
