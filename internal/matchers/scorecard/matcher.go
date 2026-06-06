package scorecard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/matchers"
	"github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const defaultCacheTTL = 24 * time.Hour

// notScoredSentinel is cached under the same key as a successful response
// when api.scorecard.dev returns 404, so the matcher does not re-request the
// repository on every run within the cache TTL.
type notScoredSentinel struct {
	NotScored bool `json:"notScored"`
}

// Config configures the Scorecard matcher.
type Config struct {
	// APIBase overrides the api.scorecard.dev base URL. Defaults to
	// https://api.scorecard.dev.
	APIBase string
	// CacheDir overrides the on-disk cache directory. Defaults to
	// ~/.bomly/cache/scorecard.
	CacheDir string
	// CacheTTL is the time-to-live for cached responses. Defaults to 24h.
	CacheTTL time.Duration
	// BypassCache forces fresh fetches even when a cached response exists.
	BypassCache bool
	// ClientConfig overrides the HTTP client config. Useful for tests that
	// need to point at an httptest.Server or inject a custom HTTP client.
	// When non-nil, APIBase on the Config is ignored.
	ClientConfig *ClientConfig
	// Logger receives diagnostic messages. May be nil (no-op).
	Logger *zap.Logger
	// Stderr is used for user-visible warnings. May be nil.
	Stderr io.Writer
}

// DefaultConfig returns a production-ready Scorecard matcher config.
func DefaultConfig() Config {
	return Config{
		APIBase:  defaultAPIBase,
		CacheDir: defaultCacheDir(),
		CacheTTL: defaultCacheTTL,
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "scorecard")
	}
	return filepath.Join(home, ".bomly", "cache", "scorecard")
}

// Matcher attaches OpenSSF Scorecard runs to packages whose upstream source
// repository can be resolved to a github.com URL.
type Matcher struct {
	client *Client
	cache  *cache.FileCache
	config Config
	logger *zap.Logger
}

type matchStats struct {
	requestedPackages int
	unresolvedRepos   int
	uniqueRepos       int
	cacheHits         int
	cacheMisses       int
	notScoredCached   int
	apiHits           int
	apiNotFound       int
	apiFailures       int
	cacheWriteFails   int
	enrichedPackages  int
}

// New creates a Scorecard matcher.
func New(config Config) (*Matcher, error) {
	if config.CacheDir == "" {
		config.CacheDir = defaultCacheDir()
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}

	clientConfig := DefaultClientConfig()
	if config.APIBase != "" {
		clientConfig.APIBase = config.APIBase
	}
	if config.ClientConfig != nil {
		clientConfig = *config.ClientConfig
	}

	fileCache, err := cache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("scorecard matcher: %w", err)
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Matcher{
		client: NewClient(clientConfig),
		cache:  fileCache,
		config: config,
		logger: logger,
	}, nil
}

// Descriptor returns the matcher registration metadata.
func (m *Matcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:                "scorecard",
		DisplayName:         "OpenSSF Scorecard",
		Enabled:             false,
		Origin:              sdk.CoreOrigin,
		SupportedEcosystems: nil,
		Priority:            90,
		Required:            false,
		Capabilities:        []string{"project-posture"},
	}
}

// Ready reports whether this matcher can run. The Scorecard matcher only
// needs HTTP egress; no local binary or auth is required.
func (m *Matcher) Ready() bool {
	return true
}

// Applicable reports whether this matcher applies to the given request.
func (m *Matcher) Applicable(_ context.Context, req sdk.MatchRequest) (bool, error) {
	return true, nil
}

// Match resolves Scorecard runs for every package whose upstream source
// repository can be identified as a github.com URL, then attaches the result
// to those packages. The matcher never returns an error from this method:
// transport failures degrade to per-repo warnings so a bad network does not
// abort the pipeline.
func (m *Matcher) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil || req.Registry == nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{"scorecard"}, MatcherRunDetails: scorecardMatcherRuns(0)}, nil
	}
	packages := matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)
	if len(packages) == 0 {
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{"scorecard"}, MatcherRunDetails: scorecardMatcherRuns(0)}, nil
	}

	stats := matchStats{requestedPackages: len(packages)}
	m.logger.Info(fmt.Sprintf("Scorecard enriching %d packages with project posture data", len(packages)))

	// Group packages by resolved repo so we only fetch each repo once.
	reposByPkg := make(map[string]string, len(packages)) // pkg.PURL -> repo key
	pkgsByRepo := make(map[string][]*sdk.Package)
	repoOrder := make([]string, 0)
	for _, pkg := range packages {
		repo := resolveRepo(pkg)
		if repo == "" {
			stats.unresolvedRepos++
			continue
		}
		reposByPkg[pkg.PURL] = repo
		if _, seen := pkgsByRepo[repo]; !seen {
			repoOrder = append(repoOrder, repo)
		}
		pkgsByRepo[repo] = append(pkgsByRepo[repo], pkg)
	}
	stats.uniqueRepos = len(repoOrder)

	if len(repoOrder) == 0 {
		m.logger.Info(fmt.Sprintf("Scorecard enrichment skipped — no resolvable github.com repos (%d packages) in %s", stats.requestedPackages, logging.FormatDuration(time.Since(started))))
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{"scorecard"}, MatcherRunDetails: scorecardMatcherRuns(0)}, nil
	}

	// Fetch each unique repo. Cache check first; 404 is cached as a sentinel.
	scorecards := make(map[string]*sdk.PackageScorecard, len(repoOrder))
	for _, repo := range repoOrder {
		key := cache.NewKey(repo, "", "scorecard", "")

		if !m.config.BypassCache {
			if sentinel, hit := cache.Get[notScoredSentinel](m.cache, key); hit && sentinel.NotScored {
				stats.notScoredCached++
				continue
			}
			if cached, hit := cache.Get[Project](m.cache, key); hit && cached.Repo.Name != "" {
				stats.cacheHits++
				scorecards[repo] = mapProject(repo, &cached)
				continue
			}
		}
		stats.cacheMisses++

		project, err := m.client.FetchProject(ctx, repo)
		switch {
		case errors.Is(err, ErrProjectNotScored):
			stats.apiNotFound++
			if err := cache.Set(m.cache, key, notScoredSentinel{NotScored: true}); err != nil {
				stats.cacheWriteFails++
				m.logger.Debug("scorecard: cache write failed for not-scored sentinel", zap.String("repo", repo), zap.Error(err))
			}
		case err != nil:
			stats.apiFailures++
			m.logger.Warn("scorecard: fetch failed", zap.String("repo", repo), zap.Error(err))
			if m.config.Stderr != nil {
				if _, werr := fmt.Fprintf(m.config.Stderr, "warn: scorecard fetch failed for %s: %v\n", repo, err); werr != nil {
					return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{"scorecard"}, MatcherRunDetails: scorecardMatcherRuns(stats.enrichedPackages)}, werr
				}
			}
		default:
			stats.apiHits++
			if err := cache.Set(m.cache, key, *project); err != nil {
				stats.cacheWriteFails++
				m.logger.Debug("scorecard: cache write failed", zap.String("repo", repo), zap.Error(err))
			}
			scorecards[repo] = mapProject(repo, project)
		}
	}

	// Attach the resolved scorecard to every package whose repo we fetched.
	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		repo, ok := reposByPkg[pkg.PURL]
		if !ok {
			continue
		}
		card, ok := scorecards[repo]
		if !ok || card == nil {
			continue
		}
		pkg.Scorecard = card.Clone()
		pkg.Matched = true
		stats.enrichedPackages++
	}

	m.logger.Debug(
		"scorecard: enrichment summary",
		zap.Int("requested_packages", stats.requestedPackages),
		zap.Int("unresolved_repos", stats.unresolvedRepos),
		zap.Int("unique_repos", stats.uniqueRepos),
		zap.Int("cache_hits", stats.cacheHits),
		zap.Int("cache_misses", stats.cacheMisses),
		zap.Int("not_scored_cached", stats.notScoredCached),
		zap.Int("api_hits", stats.apiHits),
		zap.Int("api_not_found", stats.apiNotFound),
		zap.Int("api_failures", stats.apiFailures),
		zap.Int("cache_write_failures", stats.cacheWriteFails),
		zap.Int("enriched_packages", stats.enrichedPackages),
		zap.Bool("bypass_cache", m.config.BypassCache),
	)
	m.logger.Info(fmt.Sprintf("Scorecard enrichment attached %d packages across %d repos in %s", stats.enrichedPackages, stats.uniqueRepos, logging.FormatDuration(time.Since(started))))

	return sdk.MatchResult{
		Registry:          req.Registry,
		MatcherRuns:       []string{"scorecard"},
		MatcherRunDetails: scorecardMatcherRuns(stats.enrichedPackages),
	}, nil
}

func scorecardMatcherRuns(matchedPackages int) []sdk.MatcherRun {
	return []sdk.MatcherRun{{
		Name:            "scorecard",
		DisplayName:     "OpenSSF Scorecard",
		MatchedPackages: matchedPackages,
	}}
}
