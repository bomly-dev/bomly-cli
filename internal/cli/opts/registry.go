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
	return engine.RegistryConfigs{
		FailOn:      failOn,
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
