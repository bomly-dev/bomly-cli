// Package composition declares the build-time composition of Bomly's
// embedded (native) components as execution-neutral plugin.Module entries. The
// registry consumes Entries() and registers each module through
// Registry.RegisterModule instead of bespoke per-component wiring. Build-tag
// variants (composition_full.go / composition_lite.go) decide which
// implementation backs tag-sensitive entries such as grype.
package composition

import (
	"context"
	"fmt"
	"strings"
	"time"

	depsdev "github.com/bomly-dev/bomly-plugin-depsdev-license-matcher/plugin"
	govulncheck "github.com/bomly-dev/bomly-plugin-govulncheck-analyzer/plugin"
	grype "github.com/bomly-dev/bomly-plugin-grype-matcher/plugin"
	jsreach "github.com/bomly-dev/bomly-plugin-jsreach-analyzer/plugin"
	jvmreach "github.com/bomly-dev/bomly-plugin-jvmreach-analyzer/plugin"
	osvmatcher "github.com/bomly-dev/bomly-plugin-osv-matcher/plugin"
	pyreach "github.com/bomly-dev/bomly-plugin-pyreach-analyzer/plugin"
	scorecard "github.com/bomly-dev/bomly-plugin-scorecard-matcher/plugin"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/httpkit"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Implementation values accepted by Entry.Implementation.
const (
	// ImplementationNative marks a component compiled into the host binary.
	ImplementationNative = "native"
	// ImplementationPlugin marks a component backed by an external managed
	// plugin process.
	ImplementationPlugin = "plugin"
)

// Deps carries the host-resolved inputs module constructors need. It mirrors
// what the registry's bespoke matcher/analyzer wiring used to pass:
// configuration overrides, the shared logger, and the shared HTTP client
// provider.
type Deps struct {
	Logger             *zap.Logger
	HTTPClientProvider *httpkit.ClientProvider

	OsvAPIBase  string
	OsvCacheDir string
	OsvCacheTTL string
	KEVCacheDir string
	KEVCacheTTL string

	ScorecardAPIBase  string
	ScorecardCacheDir string
	ScorecardCacheTTL string

	// Grype database refresh settings. The switch arrives as a bool because
	// the CLI boundary reads the matchers.grype.db_auto_update string once,
	// with the grammar config.Validate accepted; the durations arrive as the
	// Go duration strings the configuration carries, empty meaning the
	// matcher's own default.
	GrypeDBUpdateDisabled      bool
	GrypeDBMaxAge              string
	GrypeDBUpdateCheckInterval string
}

func (d Deps) logger() *zap.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return zap.NewNop()
}

// Entry describes one composed component.
type Entry struct {
	// Name is the component's descriptor name.
	Name string
	// Kind is the component's plugin kind.
	Kind plugin.PluginKind
	// Implementation is ImplementationNative or ImplementationPlugin.
	Implementation string
	// DefaultEnabled reports whether the component runs without explicit
	// selection.
	DefaultEnabled bool
	// Module builds the execution-neutral module for this entry.
	Module func(Deps) plugin.Module
}

// Origin maps the entry's implementation and the requested execution mode to
// the component origin the registry records. Native components must run
// embedded: a native entry combined with any non-embedded execution is a
// composition bug and is rejected.
func (e Entry) Origin(execution plugin.ExecutionMode) (plugin.DetectorOrigin, error) {
	switch e.Implementation {
	case ImplementationNative:
		if execution != plugin.ExecutionEmbedded {
			return "", fmt.Errorf("composition entry %q: native components must run embedded, got execution mode %q", e.Name, execution)
		}
		return plugin.CoreOrigin, nil
	case ImplementationPlugin:
		return plugin.ExternalOrigin, nil
	default:
		return "", fmt.Errorf("composition entry %q: unknown implementation %q", e.Name, e.Implementation)
	}
}

// Entries returns the composed component entries for this build variant, in
// registration order.
func Entries() []Entry {
	entries := make([]Entry, 0, 8)
	entries = append(entries, grypeEntry())
	entries = append(entries,
		osvEntry(),
		depsDevEntry(),
		scorecardEntry(),
		govulncheckEntry(),
		jsReachEntry(),
		pyReachEntry(),
		jvmReachEntry(),
	)
	return entries
}

// osvEntry composes the OSV matcher. It is opt-in: the default --enrich set
// runs grype for vulnerabilities and deps.dev for licenses, and OSV joins it
// with --matchers +osv (ADR-0048). The generated matcher docs read this flag
// through internal/support, so a page cannot describe a default set the
// binary does not run; they did for four months after PR #130 flipped it.
// grypeMatcher builds the Grype matcher from the resolved database settings.
// config.Validate already rejects malformed durations on the CLI path, so a
// parse failure here means a host that bypassed it; it logs and leaves the
// matcher's own default in place rather than aborting enrichment.
func grypeMatcher(deps Deps) grype.Matcher {
	logger := deps.logger()
	matcher := grype.Matcher{Logger: logger, DisableDBUpdate: deps.GrypeDBUpdateDisabled}
	matcher.DBMaxAge = durationSetting(logger, "grype: invalid db_max_age; using default", deps.GrypeDBMaxAge)
	matcher.DBUpdateCheckInterval = durationSetting(logger, "grype: invalid db_update_check_interval; using default", deps.GrypeDBUpdateCheckInterval)
	return matcher
}

// durationSetting parses an optional duration setting; empty and malformed
// values both yield zero, which every consumer reads as "use the default".
func durationSetting(logger *zap.Logger, warning, raw string) time.Duration {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		logger.Warn(warning, zap.String("value", raw), zap.Error(err))
		return 0
	}
	return parsed
}

func osvEntry() Entry {
	return Entry{
		Name:           "osv",
		Kind:           plugin.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: false,
		Module: func(deps Deps) plugin.Module {
			return plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
				Descriptor: plugin.MatcherDescriptor{Name: "osv", DisplayName: "OSV"},
				New: func(_ context.Context, _ plugin.HostContext) (plugin.Matcher, error) {
					logger := deps.logger()
					cfg := osvmatcher.DefaultConfig()
					cfg.Logger = logger
					cfg.HTTPClientProvider = deps.HTTPClientProvider
					if deps.OsvAPIBase != "" {
						cfg.APIBase = deps.OsvAPIBase
					}
					if deps.OsvCacheDir != "" {
						cfg.CacheDir = deps.OsvCacheDir
					}
					if deps.OsvCacheTTL != "" {
						if d, err := time.ParseDuration(deps.OsvCacheTTL); err == nil {
							cfg.CacheTTL = d
						} else {
							logger.Warn("osv: invalid cache_ttl; using default", zap.String("value", deps.OsvCacheTTL), zap.Error(err))
						}
					}
					if deps.KEVCacheDir != "" {
						cfg.KEVCacheDir = deps.KEVCacheDir
					}
					if deps.KEVCacheTTL != "" {
						if d, err := time.ParseDuration(deps.KEVCacheTTL); err == nil {
							cfg.KEVCacheTTL = d
						} else {
							logger.Warn("osv: invalid kev_cache_ttl; using default", zap.String("value", deps.KEVCacheTTL), zap.Error(err))
						}
					}
					return osvmatcher.New(cfg)
				},
			}}
		},
	}
}

func depsDevEntry() Entry {
	return Entry{
		Name:           "depsdev-license-matcher",
		Kind:           plugin.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: true,
		Module: func(deps Deps) plugin.Module {
			return plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
				Descriptor: plugin.MatcherDescriptor{Name: "depsdev-license-matcher", DisplayName: "deps.dev License Matcher"},
				New: func(_ context.Context, _ plugin.HostContext) (plugin.Matcher, error) {
					cfg := depsdev.DefaultConfig()
					cfg.Logger = deps.logger()
					cfg.HTTPClientProvider = deps.HTTPClientProvider
					matcher, err := depsdev.New(cfg)
					if err != nil {
						return nil, err
					}
					deps.logger().Debug("deps.dev matcher configured")
					return matcher, nil
				},
			}}
		},
	}
}

func scorecardEntry() Entry {
	return Entry{
		Name:           "scorecard",
		Kind:           plugin.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: false,
		Module: func(deps Deps) plugin.Module {
			return plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
				Descriptor: plugin.MatcherDescriptor{Name: "scorecard", DisplayName: "OpenSSF Scorecard"},
				New: func(_ context.Context, _ plugin.HostContext) (plugin.Matcher, error) {
					logger := deps.logger()
					cfg := scorecard.DefaultConfig()
					cfg.Logger = logger
					if deps.ScorecardAPIBase != "" {
						cfg.APIBase = deps.ScorecardAPIBase
					}
					if deps.ScorecardCacheDir != "" {
						cfg.CacheDir = deps.ScorecardCacheDir
					}
					if deps.ScorecardCacheTTL != "" {
						if d, err := time.ParseDuration(deps.ScorecardCacheTTL); err == nil {
							cfg.CacheTTL = d
						} else {
							logger.Warn("scorecard: invalid cache_ttl; using default", zap.String("value", deps.ScorecardCacheTTL), zap.Error(err))
						}
					}
					cfg.ClientConfig = &scorecard.ClientConfig{
						APIBase:            cfg.APIBase,
						Timeout:            15 * time.Second,
						HTTPClientProvider: deps.HTTPClientProvider,
					}
					matcher, err := scorecard.New(cfg)
					if err != nil {
						return nil, err
					}
					logger.Debug("scorecard matcher configured",
						zap.String("api_base", logging.SanitizeURL(cfg.APIBase)),
						zap.String("cache_dir", cfg.CacheDir),
						zap.Duration("cache_ttl", cfg.CacheTTL),
					)
					return matcher, nil
				},
			}}
		},
	}
}

func govulncheckEntry() Entry {
	return analyzerEntry("govulncheck", func(deps Deps) plugin.Analyzer {
		return govulncheck.Analyzer{Logger: deps.logger()}
	})
}

func jsReachEntry() Entry {
	return analyzerEntry("jsreach", func(deps Deps) plugin.Analyzer {
		return jsreach.Analyzer{Logger: deps.logger()}
	})
}

func pyReachEntry() Entry {
	return analyzerEntry("pyreach", func(deps Deps) plugin.Analyzer {
		return pyreach.Analyzer{Logger: deps.logger()}
	})
}

func jvmReachEntry() Entry {
	return analyzerEntry("jvmreach", func(deps Deps) plugin.Analyzer {
		return jvmreach.Analyzer{Logger: deps.logger()}
	})
}

func analyzerEntry(name string, build func(Deps) plugin.Analyzer) Entry {
	return Entry{
		Name:           name,
		Kind:           plugin.PluginKindAnalyzer,
		Implementation: ImplementationNative,
		DefaultEnabled: true,
		Module: func(deps Deps) plugin.Module {
			return plugin.Module{Kind: plugin.PluginKindAnalyzer, Analyzer: &plugin.AnalyzerModule{
				Descriptor: plugin.AnalyzerDescriptor{Name: name},
				New: func(_ context.Context, _ plugin.HostContext) (plugin.Analyzer, error) {
					return build(deps), nil
				},
			}}
		},
	}
}
