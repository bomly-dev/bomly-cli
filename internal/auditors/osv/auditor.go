package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	audcache "github.com/bomly/bomly-cli/internal/auditors/cache"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

const (
	defaultCacheTTL      = 24 * time.Hour
	defaultVulnDetailTTL = 7 * 24 * time.Hour // vuln records are stable once published
)

// Config configures the OSV auditor.
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
	// ProxyURL is an optional HTTP proxy URL for external network requests.
	ProxyURL string
	// Logger receives diagnostic messages. May be nil (no-op).
	Logger *zap.Logger
	// Stderr is used for progress messages. May be nil.
	Stderr io.Writer
}

// DefaultConfig returns a production-ready OSV auditor config.
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

// Auditor implements scan.Auditor using the OSV API.
type Auditor struct {
	client      *Client
	cache       *audcache.FileCache
	detailCache *audcache.FileCache // keyed by vuln ID; holds full OsvVulnerability
	kevCache    *audcache.FileCache
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

// New creates a new OSV auditor. Returns an error if the cache directory
// cannot be created.
func New(config Config) (*Auditor, error) {
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
	if config.ProxyURL != "" {
		clientConfig.ProxyURL = config.ProxyURL
	}

	cache, err := audcache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("osv auditor: %w", err)
	}
	kevCache, err := audcache.NewFileCache(config.KEVCacheDir, config.KEVCacheTTL)
	if err != nil {
		// KEV cache init failure is non-fatal; we'll skip caching KEV results.
		kevCache = nil
	}
	detailCache, err := audcache.NewFileCache(config.VulnDetailCacheDir, config.VulnDetailCacheTTL)
	if err != nil {
		// Detail cache failure is non-fatal; we'll fetch without caching.
		detailCache = nil
	}

	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Auditor{
		client:      NewClient(clientConfig),
		cache:       cache,
		detailCache: detailCache,
		kevCache:    kevCache,
		config:      config,
		logger:      logger,
	}, nil
}

// Descriptor returns the auditor registration metadata.
func (a *Auditor) Descriptor() scan.AuditorDescriptor {
	return scan.AuditorDescriptor{
		Name:               "osv",
		ImplementationType: scan.NativeDetector,
		// nil SupportedEcosystems means all ecosystems; OSV handles ecosystem
		// selection internally via PURL or name+ecosystem queries.
		SupportedEcosystems: nil,
		SupportedModes: []scan.TargetMode{
			scan.TargetModeFullGraph,
			scan.TargetModeComponent,
		},
		Priority: 100,
		Required: false,
	}
}

// Ready reports whether this auditor can run. OSV requires no local binary.
func (a *Auditor) Ready() bool {
	return true
}

// Applicable reports whether this auditor applies to the given request.
func (a *Auditor) Applicable(_ context.Context, req scan.AuditRequest) (bool, error) {
	return req.Mode == scan.TargetModeFullGraph || req.Mode == scan.TargetModeComponent, nil
}

// Audit resolves vulnerabilities for all packages in the graph.
func (a *Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return scan.AuditResult{}, nil
	}

	packages := req.Graph.Packages()
	if req.Mode == scan.TargetModeComponent && req.Target != nil {
		packages = []*model.Package{req.Target}
	}
	if len(packages) == 0 {
		return scan.AuditResult{Graph: req.Graph, Target: req.Target}, nil
	}

	stats := auditStats{requestedPackages: len(packages)}
	a.logger.Info(fmt.Sprintf("OSV auditing %d packages for vulnerabilities", len(packages)))

	type indexedPkg struct {
		pkg   *model.Package
		key   audcache.Key
		query BatchQuery
	}

	var toFetch []indexedPkg
	var allFindings []scan.Finding

	// First pass: try cache
	for _, pkg := range packages {
		key, query, ok := buildQuery(pkg)
		if !ok {
			stats.skippedPackages++
			continue
		}
		if !a.config.BypassCache {
			if found, hit := audcache.Get[[]OsvVulnerability](a.cache, key); hit {
				stats.cacheHits++
				stats.cachedFindings += len(found)
				for _, v := range found {
					allFindings = append(allFindings, MapVulnerability(v, pkg))
				}
				continue
			}
		}
		stats.cacheMisses++
		toFetch = append(toFetch, indexedPkg{pkg: pkg, key: key, query: query})
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
			// Non-fatal: return what we have with a warning.
			a.logger.Warn("osv: batch query failed", zap.Error(err))
			if a.config.Stderr != nil {
				fmt.Fprintf(a.config.Stderr, "warn: osv query failed: %v\n", err)
			}
			return scan.AuditResult{Graph: req.Graph, Target: req.Target, Findings: allFindings}, nil
		}

		for i, result := range results {
			item := toFetch[i]
			// Collect unique vuln IDs from the querybatch stub response.
			ids := make([]string, 0, len(result.Vulns))
			for _, ref := range result.Vulns {
				ids = append(ids, ref.ID)
			}
			// Fetch full details for each ID (checks detail cache first).
			details := a.fetchVulnDetails(ids, &stats)
			// Build full OsvVulnerability slice for package-level caching.
			vulns := make([]OsvVulnerability, 0, len(result.Vulns))
			for _, ref := range result.Vulns {
				if full, ok := details[ref.ID]; ok {
					vulns = append(vulns, *full)
				} else {
					vulns = append(vulns, OsvVulnerability{ID: ref.ID, Modified: ref.Modified})
				}
			}
			// Cache the full objects at the package level (24 h TTL).
			if err := audcache.Set(a.cache, item.key, vulns); err != nil {
				stats.packageCacheWriteFails++
			}
			stats.apiFindings += len(vulns)
			for _, v := range vulns {
				allFindings = append(allFindings, MapVulnerability(v, item.pkg))
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

	a.logger.Info(fmt.Sprintf("OSV audit found %d findings in %s", len(allFindings), logging.FormatDuration(time.Since(started))))

	// Optional KEV enrichment pass.
	if a.config.EnableKEV && len(allFindings) > 0 {
		a.logger.Debug("osv: starting KEV enrichment")
		catalog, err := FetchKEVCatalog(a.kevCache, a.config.ProxyURL)
		if err != nil {
			a.logger.Warn("osv: kev catalog unavailable", zap.Error(err))
			if a.config.Stderr != nil {
				fmt.Fprintf(a.config.Stderr, "warn: kev catalog unavailable: %v\n", err)
			}
		} else {
			pre := len(allFindings)
			allFindings = markKEVFindings(allFindings, catalog)
			a.logger.Debug("osv: KEV enrichment complete", zap.Int("findings", pre))
		}
	}

	return scan.AuditResult{
		Graph:    req.Graph,
		Target:   req.Target,
		Findings: allFindings,
	}, nil
}

// fetchVulnDetails retrieves full OsvVulnerability records for the given IDs,
// checking the detail cache first and fetching from the OSV API for misses.
// IDs that cannot be fetched are returned as stubs with only the ID set.
func (a *Auditor) fetchVulnDetails(ids []string, stats *auditStats) map[string]*OsvVulnerability {
	result := make(map[string]*OsvVulnerability, len(ids))
	var toFetch []string
	if stats != nil {
		stats.detailRequested += len(ids)
	}
	for _, id := range ids {
		key := audcache.NewKey(id, "", "", "")
		if a.detailCache != nil {
			if found, hit := audcache.Get[OsvVulnerability](a.detailCache, key); hit {
				if stats != nil {
					stats.detailCacheHits++
				}
				v := found
				result[id] = &v
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
			result[id] = &OsvVulnerability{ID: id} // stub so we still emit the finding
			continue
		}
		if stats != nil {
			stats.detailFetched++
		}
		key := audcache.NewKey(id, "", "", "")
		if a.detailCache != nil {
			if err := audcache.Set(a.detailCache, key, *vuln); err != nil && stats != nil {
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

// buildQuery constructs a CacheKey and BatchQuery for a package.
// Returns (key, query, true) when the package has enough information to query OSV.
// Returns (_, _, false) when the package should be skipped.
func buildQuery(pkg *model.Package) (audcache.Key, BatchQuery, bool) {
	if pkg.Version == "" {
		// OSV requires a version for meaningful results.
		return audcache.Key{}, BatchQuery{}, false
	}

	// Prefer PURL
	if pkg.PURL != "" {
		key := audcache.NewKey(pkg.PURL, "", "", "")
		purlPkg := PurlPackage{Purl: pkg.PURL}
		raw, _ := json.Marshal(purlPkg)
		return key, BatchQuery{Package: raw}, true
	}

	// Fall back to name + ecosystem + version
	ecosystem := ecosystemToOSV(pkg.Ecosystem)
	if ecosystem == "" {
		return audcache.Key{}, BatchQuery{}, false
	}

	key := audcache.NewKey("", pkg.Name, ecosystem, pkg.Version)
	namePkg := NamePackage{Name: pkg.Name, Ecosystem: ecosystem}
	raw, _ := json.Marshal(namePkg)
	return key, BatchQuery{Package: raw, Version: pkg.Version}, true
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

// markKEVFindings appends a KEV reason to any finding whose ID or aliases
// appear in the KEV catalog.
func markKEVFindings(findings []scan.Finding, catalog *KEVCatalog) []scan.Finding {
	for i := range findings {
		aliases := extractAliasesFromReasons(findings[i].Reasons)
		if catalog.Contains(findings[i].ID, aliases) {
			findings[i].Reasons = append(findings[i].Reasons, "CISA KEV: actively exploited in the wild")
		}
	}
	return findings
}

func extractAliasesFromReasons(reasons []string) []string {
	const prefix = "Also known as: "
	for _, r := range reasons {
		if len(r) > len(prefix) && r[:len(prefix)] == prefix {
			parts := strings.Split(r[len(prefix):], ",")
			result := make([]string, 0, len(parts))
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
			return result
		}
	}
	return nil
}
