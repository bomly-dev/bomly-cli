// Package composition declares the build-time composition of Bomly's
// embedded (native) components as execution-neutral sdk.Module entries. The
// registry consumes Entries() and registers each module through
// Registry.RegisterModule instead of bespoke per-component wiring. Build-tag
// variants (composition_full.go / composition_lite.go) decide which
// implementation backs tag-sensitive entries such as grype.
package composition

import (
	"context"
	"fmt"
	"time"

	"github.com/bomly-dev/bomly-cli/components/analyzers/govulncheck"
	"github.com/bomly-dev/bomly-cli/components/analyzers/jsreach"
	"github.com/bomly-dev/bomly-cli/components/analyzers/jvmreach"
	"github.com/bomly-dev/bomly-cli/components/analyzers/pyreach"
	"github.com/bomly-dev/bomly-cli/internal/matchers/depsdev"
	osvmatcher "github.com/bomly-dev/bomly-cli/internal/matchers/osv"
	"github.com/bomly-dev/bomly-cli/internal/matchers/scorecard"
	"github.com/bomly-dev/bomly-sdk"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"go.uber.org/zap"
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
	HTTPClientProvider *sdk.HTTPClientProvider

	OsvAPIBase  string
	OsvCacheDir string
	OsvCacheTTL string
	KEVCacheDir string
	KEVCacheTTL string

	ScorecardAPIBase  string
	ScorecardCacheDir string
	ScorecardCacheTTL string
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
	Kind sdk.PluginKind
	// Implementation is ImplementationNative or ImplementationPlugin.
	Implementation string
	// DefaultEnabled reports whether the component runs without explicit
	// selection.
	DefaultEnabled bool
	// Module builds the execution-neutral module for this entry.
	Module func(Deps) sdk.Module
}

// Origin maps the entry's implementation and the requested execution mode to
// the component origin the registry records. Native components must run
// embedded: a native entry combined with any non-embedded execution is a
// composition bug and is rejected.
func (e Entry) Origin(execution sdk.ExecutionMode) (sdk.DetectorOrigin, error) {
	switch e.Implementation {
	case ImplementationNative:
		if execution != sdk.ExecutionEmbedded {
			return "", fmt.Errorf("composition entry %q: native components must run embedded, got execution mode %q", e.Name, execution)
		}
		return sdk.CoreOrigin, nil
	case ImplementationPlugin:
		return sdk.ExternalOrigin, nil
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

func osvEntry() Entry {
	return Entry{
		Name:           "osv",
		Kind:           sdk.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: false,
		Module: func(deps Deps) sdk.Module {
			return sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
				Descriptor: sdk.MatcherDescriptor{Name: "osv", DisplayName: "OSV"},
				New: func(_ context.Context, _ sdk.HostContext) (sdk.Matcher, error) {
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
		Kind:           sdk.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: true,
		Module: func(deps Deps) sdk.Module {
			return sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
				Descriptor: sdk.MatcherDescriptor{Name: "depsdev-license-matcher", DisplayName: "deps.dev License Matcher"},
				New: func(_ context.Context, _ sdk.HostContext) (sdk.Matcher, error) {
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
		Kind:           sdk.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: false,
		Module: func(deps Deps) sdk.Module {
			return sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
				Descriptor: sdk.MatcherDescriptor{Name: "scorecard", DisplayName: "OpenSSF Scorecard"},
				New: func(_ context.Context, _ sdk.HostContext) (sdk.Matcher, error) {
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
	return analyzerEntry("govulncheck", govulncheck.Module)
}

func jsReachEntry() Entry {
	return analyzerEntry("jsreach", jsreach.Module)
}

func pyReachEntry() Entry {
	return analyzerEntry("pyreach", pyreach.Module)
}

func jvmReachEntry() Entry {
	return analyzerEntry("jvmreach", jvmreach.Module)
}

// analyzerEntry wraps a component module constructor from
// components/analyzers/<name>. The component builds its analyzer from the
// registration HostContext (logger included), so the entry ignores Deps.
func analyzerEntry(name string, module func() sdk.Module) Entry {
	return Entry{
		Name:           name,
		Kind:           sdk.PluginKindAnalyzer,
		Implementation: ImplementationNative,
		DefaultEnabled: true,
		Module:         func(Deps) sdk.Module { return module() },
	}
}
