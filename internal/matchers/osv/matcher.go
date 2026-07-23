package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	defaultCacheTTL      = 24 * time.Hour
	defaultVulnDetailTTL = 7 * 24 * time.Hour // vuln records are stable once published
)

// Config configures the OSV matcher.
type Config struct {
	// APIBase overrides the OSV API base URL. Defaults to https://api.osv.dev.
	APIBase string
	// CacheDir overrides the cache directory. Defaults to ~/.bomly/cache/osv.
	CacheDir string
	// CacheTTL is the time-to-live for cached results. Defaults to 24 hours.
	CacheTTL time.Duration
	// BypassCache forces a fresh fetch even when a cached result exists.
	BypassCache bool
	// EnableKEV enables the KEV enrichment pass. Defaults to true.
	EnableKEV bool
	// KEVCacheDir overrides the KEV cache directory. Defaults to ~/.bomly/cache/kev.
	KEVCacheDir string
	// KEVCacheTTL is the TTL for the cached KEV catalog. Defaults to 6 hours.
	KEVCacheTTL time.Duration
	// VulnDetailCacheDir overrides the vuln-detail cache directory.
	// Defaults to ~/.bomly/cache/osv-vulns.
	VulnDetailCacheDir string
	// VulnDetailCacheTTL is the TTL for cached per-vuln detail records.
	// Defaults to 7 days (vuln records seldom change once published).
	VulnDetailCacheTTL time.Duration
	// Logger receives diagnostic messages. Maybe nil (no-op).
	Logger *zap.Logger
	// Stderr is used for progress messages. Maybe nil.
	Stderr io.Writer
	// Client overrides the OSV HTTP client. Maybe nil.
	Client *http.Client
	// KEVClient overrides the CISA KEV HTTP client. Maybe nil.
	KEVClient *http.Client
	// HTTPClientProvider supplies shared HTTP clients when Client/KEVClient are nil.
	HTTPClientProvider *sdk.HTTPClientProvider
}

// DefaultConfig returns a production-ready OSV matcher config.
func DefaultConfig() Config {
	return Config{
		APIBase:     "",
		CacheDir:    defaultCacheDir(),
		CacheTTL:    defaultCacheTTL,
		BypassCache: false,
		EnableKEV:   true,
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "osv")
	}
	return filepath.Join(home, ".bomly", "cache", "osv")
}

func defaultKEVCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "kev")
	}
	return filepath.Join(home, ".bomly", "cache", "kev")
}

func defaultVulnDetailCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "osv-vulns")
	}
	return filepath.Join(home, ".bomly", "cache", "osv-vulns")
}

// Matcher implements matchers.Matcher using the OSV API.
type Matcher struct {
	client      *Client
	cache       *cache.FileCache
	detailCache *cache.FileCache // keyed by vuln ID; holds full OsvVulnerability
	kevCache    *cache.FileCache
	config      Config
	logger      *zap.Logger
}

type auditStats struct {
	requestedPackages      int
	skippedPackages        int
	cacheHits              int
	cacheMisses            int
	cachedFindings         int
	apiPackages            int
	apiFindings            int
	packageCacheWriteFails int
	detailRequested        int
	detailCacheHits        int
	detailCacheMisses      int
	detailFetched          int
	detailFetchFailures    int
	detailCacheUnavailable int
	detailCacheWriteFails  int
}

// New creates a new OSV matcher. Returns an error if the cache directory
// cannot be created.
func New(config Config) (*Matcher, error) {
	if config.CacheDir == "" {
		config.CacheDir = defaultCacheDir()
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if config.KEVCacheDir == "" {
		config.KEVCacheDir = defaultKEVCacheDir()
	}
	if config.KEVCacheTTL == 0 {
		config.KEVCacheTTL = defaultKEVCacheTTL
	}

	if config.VulnDetailCacheDir == "" {
		config.VulnDetailCacheDir = defaultVulnDetailCacheDir()
	}
	if config.VulnDetailCacheTTL == 0 {
		config.VulnDetailCacheTTL = defaultVulnDetailTTL
	}

	clientConfig := DefaultClientConfig()
	if config.APIBase != "" {
		clientConfig.APIBase = config.APIBase
	}
	clientConfig.HTTPClient = config.Client
	clientConfig.HTTPClientProvider = config.HTTPClientProvider
	if config.KEVClient == nil && config.HTTPClientProvider != nil {
		config.KEVClient = config.HTTPClientProvider.Client(kevFetchTimeout)
	}

	c, err := cache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("osv auditor: %w", err)
	}
	kevCache, err := cache.NewFileCache(config.KEVCacheDir, config.KEVCacheTTL)
	if err != nil {
		// KEV cache init failure is non-fatal; we'll skip caching KEV results.
		kevCache = nil
	}
	detailCache, err := cache.NewFileCache(config.VulnDetailCacheDir, config.VulnDetailCacheTTL)
	if err != nil {
		// Detail cache failure is non-fatal; we'll fetch without caching.
		detailCache = nil
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Matcher{
		client:      NewClient(clientConfig),
		cache:       c,
		detailCache: detailCache,
		kevCache:    kevCache,
		config:      config,
		logger:      logger,
	}, nil
}

// Descriptor returns the matcher registration metadata.
func (a *Matcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:        "osv",
		DisplayName: "OSV",
		// nil SupportedEcosystems means all ecosystems; OSV handles ecosystem
		// selection internally via PURL or name+ecosystem queries.
		SupportedEcosystems: nil,
	}
}

// Ready reports whether this matcher can run. OSV requires no local binary.
func (a *Matcher) Ready(context.Context, sdk.MatchRequest) error {
	return nil
}

// Applicable reports whether this matcher applies to the given request.
func (a *Matcher) Applicable(_ context.Context, _ sdk.MatchRequest) (bool, error) {
	return true, nil
}

// Match resolves vulnerabilities for all dependencies in the graph and attaches
// them to the PURL-keyed package registry.
func (a *Matcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil || req.Registry == nil {
		return sdk.MatchResult{Registry: req.Registry}, nil
	}

	deps := req.Graph.Nodes()
	if req.Target != nil {
		deps = []*sdk.Dependency{req.Target}
	}
	if len(deps) == 0 {
		return sdk.MatchResult{Registry: req.Registry}, nil
	}

	stats := auditStats{requestedPackages: len(deps)}
	a.logger.Info(fmt.Sprintf("OSV enriching %d packages with vulnerability data", len(deps)))

	type indexedPkg struct {
		purl  string
		key   cache.Key
		query BatchQuery
	}

	var toFetch []indexedPkg
	// enriched is keyed by canonical PURL.
	enriched := make(map[string][]sdk.Vulnerability, len(deps))
	seenPURL := make(map[string]struct{}, len(deps))

	// First pass: try cache
	for _, dep := range deps {
		if !sdk.NodeIsEnrichable(dep) {
			// First-party artifacts (workspace members, reactor modules, the
			// project's own package) are absent from OSV; querying them only
			// risks coincidental name matches.
			stats.skippedPackages++
			continue
		}
		purl := sdk.CanonicalPackageURLFromDependency(dep)
		if purl == "" {
			stats.skippedPackages++
			continue
		}
		if _, done := seenPURL[purl]; done {
			continue
		}
		seenPURL[purl] = struct{}{}
		key, query, ok := buildQuery(dep, purl)
		if !ok {
			stats.skippedPackages++
			continue
		}
		if !a.config.BypassCache {
			if found, hit := cache.Get[[]Vulnerability](a.cache, key); hit {
				stats.cacheHits++
				stats.cachedFindings += len(found)
				for _, v := range found {
					enriched[purl] = append(enriched[purl], MapVulnerability(v))
				}
				continue
			}
		}
		stats.cacheMisses++
		toFetch = append(toFetch, indexedPkg{purl: purl, key: key, query: query})
	}
	a.logger.Debug(
		"osv: package cache summary",
		zap.Int("requested", stats.requestedPackages),
		zap.Int("cache_hits", stats.cacheHits),
		zap.Int("cache_misses", stats.cacheMisses),
		zap.Int("cached_findings", stats.cachedFindings),
		zap.Int("skipped", stats.skippedPackages),
		zap.Bool("bypass_cache", a.config.BypassCache),
	)

	// Second pass: batch fetch uncached
	if len(toFetch) > 0 {
		stats.apiPackages = len(toFetch)
		a.logger.Info(fmt.Sprintf("Fetching %d packages from OSV API", len(toFetch)))
		queries := make([]BatchQuery, len(toFetch))
		for i, item := range toFetch {
			queries[i] = item.query
		}
		results, err := a.client.QueryBatch(queries)
		if err != nil {
			// Return partial enrichment together with the error. The engine
			// degrades matcher failures into pipeline warnings while preserving
			// any cache-backed evidence already collected.
			a.logger.Warn("osv: batch query failed", zap.Error(err))
			if a.config.Stderr != nil {
				if _, werr := fmt.Fprintf(a.config.Stderr, "warn: osv query failed: %v\n", err); werr != nil {
					return sdk.MatchResult{}, fmt.Errorf("osv write query warning: %w", werr)
				}
			}
			applyPackageVulnerabilityEnrichment(req.Registry, deps, enriched)
			return sdk.MatchResult{
				Registry:     req.Registry,
				MatcherStats: osvMatcherStats(enriched, stats.requestedPackages),
			}, fmt.Errorf("osv batch query: %w", err)
		}

		for i, result := range results {
			item := toFetch[i]
			// Collect unique vuln IDs from the query batch stub response.
			ids := make([]string, 0, len(result.Vulns))
			for _, ref := range result.Vulns {
				ids = append(ids, ref.ID)
			}
			// Fetch full details for each ID (checks detail cache first).
			details := a.fetchVulnDetails(ids, &stats)
			// Build full Vulnerability slice for package-level caching.
			vulns := make([]Vulnerability, 0, len(result.Vulns))
			for _, ref := range result.Vulns {
				if full, ok := details[ref.ID]; ok {
					vulns = append(vulns, *full)
				} else {
					vulns = append(vulns, Vulnerability{ID: ref.ID, Modified: ref.Modified})
				}
			}
			// Cache the full objects at the package level (24 h TTL).
			if err := cache.Set(a.cache, item.key, vulns); err != nil {
				stats.packageCacheWriteFails++
			}
			stats.apiFindings += len(vulns)
			for _, v := range vulns {
				enriched[item.purl] = append(enriched[item.purl], MapVulnerability(v))
			}
		}
		a.logger.Debug(
			"osv: api batch summary",
			zap.Int("packages", stats.apiPackages),
			zap.Int("findings", stats.apiFindings),
			zap.Int("detail_requested", stats.detailRequested),
			zap.Int("detail_cache_hits", stats.detailCacheHits),
			zap.Int("detail_cache_misses", stats.detailCacheMisses),
			zap.Int("detail_fetched", stats.detailFetched),
			zap.Int("detail_fetch_failures", stats.detailFetchFailures),
			zap.Int("package_cache_write_failures", stats.packageCacheWriteFails),
			zap.Int("detail_cache_write_failures", stats.detailCacheWriteFails),
			zap.Int("detail_cache_unavailable", stats.detailCacheUnavailable),
		)
	}

	a.logger.Info(fmt.Sprintf("OSV enrichment matched %d vulnerabilities in %s", stats.cachedFindings+stats.apiFindings, logging.FormatDuration(time.Since(started))))

	// Optional KEV enrichment pass.
	if a.config.EnableKEV && len(enriched) > 0 {
		a.logger.Debug("osv: starting KEV enrichment")
		catalog, err := FetchKEVCatalog(a.kevCache, a.config.KEVClient)
		if err != nil {
			a.logger.Warn("osv: kev catalog unavailable", zap.Error(err))
			if a.config.Stderr != nil {
				if _, werr := fmt.Fprintf(a.config.Stderr, "warn: kev catalog unavailable: %v\n", err); werr != nil {
					return sdk.MatchResult{}, werr
				}
			}
		} else {
			enriched = markKEVVulnerabilities(enriched, catalog)
			a.logger.Debug("osv: KEV enrichment complete", zap.Int("packages", len(enriched)))
		}
	}

	applyPackageVulnerabilityEnrichment(req.Registry, deps, enriched)
	return sdk.MatchResult{
		Registry:     req.Registry,
		MatcherStats: osvMatcherStats(enriched, stats.requestedPackages),
	}, nil
}

func osvMatcherStats(enriched map[string][]sdk.Vulnerability, requestedPackages int) sdk.MatcherStats {
	vulnerabilities := 0
	for _, entries := range enriched {
		vulnerabilities += len(entries)
	}
	unmatchedPackages := requestedPackages - len(enriched)
	if unmatchedPackages < 0 {
		unmatchedPackages = 0
	}
	return sdk.MatcherStats{
		Name:              "osv",
		DisplayName:       "OSV",
		MatchedPackages:   len(enriched),
		UnmatchedPackages: unmatchedPackages,
		Vulnerabilities:   vulnerabilities,
	}
}

// fetchVulnDetails retrieves full OsvVulnerability records for the given IDs,
// checking the detail cache first and fetching from the OSV API for misses.
func (a *Matcher) fetchVulnDetails(ids []string, stats *auditStats) map[string]*Vulnerability {
	result := make(map[string]*Vulnerability, len(ids))
	var toFetch []string
	if stats != nil {
		stats.detailRequested += len(ids)
	}
	for _, id := range ids {
		key := cache.NewKey(id, "", "", "")
		if a.detailCache != nil {
			if found, hit := cache.Get[Vulnerability](a.detailCache, key); hit {
				if stats != nil {
					stats.detailCacheHits++
				}
				result[id] = new(found)
				continue
			}
		}
		if stats != nil {
			if a.detailCache == nil {
				stats.detailCacheUnavailable++
			} else {
				stats.detailCacheMisses++
			}
		}
		toFetch = append(toFetch, id)
	}
	if len(ids) > 0 {
		a.logger.Debug(
			"osv: vulnerability detail cache summary",
			zap.Int("requested", len(ids)),
			zap.Int("cache_hits", statsValue(stats, func(s *auditStats) int { return s.detailCacheHits })),
			zap.Int("cache_misses", statsValue(stats, func(s *auditStats) int { return s.detailCacheMisses })),
			zap.Int("cache_unavailable", statsValue(stats, func(s *auditStats) int { return s.detailCacheUnavailable })),
		)
	}
	for _, id := range toFetch {
		vuln, err := a.client.GetVuln(id)
		if err != nil {
			if stats != nil {
				stats.detailFetchFailures++
			}
			a.logger.Warn("osv: failed to fetch vulnerability detail", zap.String("id", id), zap.Error(err))
			result[id] = &Vulnerability{ID: id} // stub so we still emit the finding
			continue
		}
		if stats != nil {
			stats.detailFetched++
		}
		key := cache.NewKey(id, "", "", "")
		if a.detailCache != nil {
			if err := cache.Set(a.detailCache, key, *vuln); err != nil && stats != nil {
				stats.detailCacheWriteFails++
			}
		}
		result[id] = vuln
	}
	return result
}

func statsValue(stats *auditStats, getter func(*auditStats) int) int {
	if stats == nil {
		return 0
	}
	return getter(stats)
}

// buildQuery constructs a CacheKey and BatchQuery for a dependency.
// purl is the canonical PURL already computed for dep.
// Returns (key, query, true) when there is enough information to query OSV.
// Returns (_, _, false) when the dependency should be skipped.
func buildQuery(dep *sdk.Dependency, purl string) (cache.Key, BatchQuery, bool) {
	if dep.Version == "" {
		// OSV requires a version for meaningful results.
		return cache.Key{}, BatchQuery{}, false
	}

	// Prefer PURL
	if purl != "" {
		key := cache.NewKey(purl, "", "", "")
		purlPkg := PurlPackage{Purl: purl}
		raw, _ := json.Marshal(purlPkg)
		return key, BatchQuery{Package: raw}, true
	}

	// Fall back to name + ecosystem + version
	ecosystem := ecosystemToOSV(string(dep.Ecosystem))
	if ecosystem == "" {
		return cache.Key{}, BatchQuery{}, false
	}

	key := cache.NewKey("", dep.Name, ecosystem, dep.Version)
	namePkg := NamePackage{Name: dep.Name, Ecosystem: ecosystem}
	raw, _ := json.Marshal(namePkg)
	return key, BatchQuery{Package: raw, Version: dep.Version}, true
}

// ecosystemToOSV maps Bomly ecosystem identifiers to OSV ecosystem names.
// See: https://ossf.github.io/osv-schema/#affectedpackage-field
func ecosystemToOSV(eco string) string {
	switch eco {
	case "npm":
		return "npm"
	case "go":
		return "Go"
	case "python":
		return "PyPI"
	case "maven":
		return "Maven"
	case "rust":
		return "crates.io"
	case "ruby":
		return "RubyGems"
	case "dart":
		return "Pub"
	case "php":
		return "Packagist"
	case "dotnet":
		return "NuGet"
	case "swift":
		return "SwiftURL"
	case "haskell":
		return "Hackage"
	case "r":
		return "CRAN"
	default:
		return ""
	}
}

// markKEVVulnerabilities appends KEV state to any vulnerability whose ID or
// aliases appear in the catalog. Keyed by PURL.
func markKEVVulnerabilities(vulnerabilities map[string][]sdk.Vulnerability, catalog *KEVCatalog) map[string][]sdk.Vulnerability {
	for purl := range vulnerabilities {
		for idx := range vulnerabilities[purl] {
			if catalog.Contains(vulnerabilities[purl][idx].ID, vulnerabilities[purl][idx].Aliases) {
				vulnerabilities[purl][idx].KEVExploited = true
				vulnerabilities[purl][idx].Reasons = append(vulnerabilities[purl][idx].Reasons, "CISA KEV: actively exploited in the wild")
			}
		}
	}
	return vulnerabilities
}

// applyPackageVulnerabilityEnrichment folds enriched vulnerabilities (keyed by
// PURL) into the registry, and marks the corresponding dependencies matched.
func applyPackageVulnerabilityEnrichment(registry *sdk.PackageRegistry, deps []*sdk.Dependency, enriched map[string][]sdk.Vulnerability) {
	if registry == nil {
		return
	}
	purlToDeps := make(map[string][]*sdk.Dependency, len(deps))
	for _, dep := range deps {
		if !sdk.NodeIsEnrichable(dep) {
			continue
		}
		purl := sdk.CanonicalPackageURLFromDependency(dep)
		if purl == "" {
			continue
		}
		purlToDeps[purl] = append(purlToDeps[purl], dep)
	}

	for purl, entries := range enriched {
		if len(entries) == 0 {
			continue
		}
		pkg := registry.Ensure(purl)
		if pkg == nil {
			continue
		}
		pkg.Matched = true
		seen := make(map[string]struct{}, len(pkg.Vulnerabilities))
		for _, vulnerability := range pkg.Vulnerabilities {
			seen[vulnerability.Source+"\x00"+vulnerability.ID] = struct{}{}
		}
		for _, entry := range entries {
			key := entry.Source + "\x00" + entry.ID
			if _, exists := seen[key]; exists {
				continue
			}
			pkg.Vulnerabilities = append(pkg.Vulnerabilities, entry.Clone())
			seen[key] = struct{}{}
		}
		for _, dep := range purlToDeps[purl] {
			dep.Matched = true
			dep.PackageRef = purl
		}
	}
}
