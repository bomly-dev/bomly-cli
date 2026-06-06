// Package depsdev implements a Bomly license matcher backed by the deps.dev API.
package depsdev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/matchers"
	"github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	// SourceType identifies deps.dev license provenance in sdk.PackageLicense.Type.
	SourceType = "external-depsdev"

	// matcherName labels this matcher in MatchResult.MatcherStats.
	matcherName = "depsdev-license-matcher"

	defaultAPIBase   = "https://api.deps.dev/v3alpha"
	defaultCacheTTL  = 24 * time.Hour
	maxBatchRequests = 5000
)

// Config configures the deps.dev license matcher.
type Config struct {
	APIBase            string
	CacheDir           string
	CacheTTL           time.Duration
	Logger             *zap.Logger
	Client             *http.Client
	HTTPClientProvider *sdk.HTTPClientProvider
}

// DefaultConfig returns a production-ready deps.dev matcher config.
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
		return filepath.Join(".bomly-cache", "licenses", "depsdev")
	}
	return filepath.Join(home, ".bomly", "cache", "licenses", "depsdev")
}

// Checker enriches package licenses from deps.dev.
type Checker struct {
	client *http.Client
	cache  *cache.FileCache
	config Config
	logger *zap.Logger
}

type pending struct {
	pkg *sdk.Package
	key cache.Key
	req versionRequest
}

type checkStats struct {
	requested          int
	unsupported        int
	cacheHits          int
	cacheMisses        int
	cacheApplied       int
	cacheLicenses      int
	apiRequests        int
	apiEnriched        int
	apiLicenses        int
	cacheWriteFailures int
	responseMisses     int
}

// New creates a deps.dev license matcher.
func New(config Config) (*Checker, error) {
	if strings.TrimSpace(config.APIBase) == "" {
		config.APIBase = defaultAPIBase
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if strings.TrimSpace(config.CacheDir) == "" {
		config.CacheDir = defaultCacheDir()
	}
	cache, err := cache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("deps.dev matcher: %w", err)
	}
	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	client := config.Client
	if client == nil {
		provider := config.HTTPClientProvider
		if provider == nil {
			provider, err = sdk.NewHTTPClientProviderFromEnv()
			if err != nil {
				return nil, fmt.Errorf("deps.dev matcher: create HTTP client provider: %w", err)
			}
		}
		client = provider.Client(20 * time.Second)
	}
	return &Checker{
		client: client,
		cache:  cache,
		config: config,
		logger: logger,
	}, nil
}

// Descriptor returns the matcher registration metadata.
func (c *Checker) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:         "depsdev-license-matcher",
		DisplayName:  "deps.dev License Matcher",
		Aliases:      []string{"deps.dev"},
		Enabled:      true,
		Origin:       sdk.CoreOrigin,
		Priority:     100,
		Required:     false,
		Capabilities: []string{"license-enrichment", "batch-http"},
	}
}

// Ready reports whether the checker can run.
func (c *Checker) Ready() bool {
	return true
}

// Applicable reports whether the checker applies to the request.
func (c *Checker) Applicable(_ context.Context, req sdk.MatchRequest) (bool, error) {
	return req.Graph != nil, nil
}

// Match enriches missing package licenses via deps.dev.
func (c *Checker) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	if req.Graph == nil || req.Registry == nil {
		return sdk.MatchResult{Registry: req.Registry, MatcherStats: matcherStats(0, 0, 0)}, nil
	}
	packages := matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)
	packages = matchers.MissingLicensePackages(packages)
	if len(packages) == 0 {
		return sdk.MatchResult{Registry: req.Registry, MatcherStats: matcherStats(0, 0, 0)}, nil
	}

	stats := checkStats{requested: len(packages)}
	pendingItems := make([]pending, 0, len(packages))
	for _, pkg := range packages {
		versionReq, cacheKey, ok := versionRequestFromPackage(pkg)
		if !ok {
			stats.unsupported++
			continue
		}
		if cached, hit := cache.Get[[]string](c.cache, cacheKey); hit {
			stats.cacheHits++
			if count := applyLicenses(pkg, cached); count > 0 {
				stats.cacheApplied++
				stats.cacheLicenses += count
			}
			continue
		}
		stats.cacheMisses++
		pendingItems = append(pendingItems, pending{pkg: pkg, key: cacheKey, req: versionReq})
	}

	for start := 0; start < len(pendingItems); start += maxBatchRequests {
		end := start + maxBatchRequests
		if end > len(pendingItems) {
			end = len(pendingItems)
		}
		chunk := pendingItems[start:end]
		if err := c.fetchBatch(ctx, chunk, &stats); err != nil {
			return sdk.MatchResult{Registry: req.Registry, MatcherStats: matcherStats(stats.cacheApplied+stats.apiEnriched, stats.requested-stats.cacheApplied-stats.apiEnriched, stats.cacheLicenses+stats.apiLicenses)}, err
		}
	}
	c.logger.Debug(
		"deps.dev: license matcher summary",
		zap.Int("requested", stats.requested),
		zap.Int("cache_hits", stats.cacheHits),
		zap.Int("cache_misses", stats.cacheMisses),
		zap.Int("cache_applied", stats.cacheApplied),
		zap.Int("cache_licenses", stats.cacheLicenses),
		zap.Int("api_requests", stats.apiRequests),
		zap.Int("api_enriched", stats.apiEnriched),
		zap.Int("api_licenses", stats.apiLicenses),
		zap.Int("response_misses", stats.responseMisses),
		zap.Int("cache_write_failures", stats.cacheWriteFailures),
		zap.Int("unsupported", stats.unsupported),
	)

	matchedPackages := stats.cacheApplied + stats.apiEnriched
	return sdk.MatchResult{
		Registry:     req.Registry,
		MatcherStats: matcherStats(matchedPackages, stats.requested-matchedPackages, stats.cacheLicenses+stats.apiLicenses),
	}, nil
}

func matcherStats(matchedPackages, unmatchedPackages, licenses int) sdk.MatcherStats {
	if unmatchedPackages < 0 {
		unmatchedPackages = 0
	}
	return sdk.MatcherStats{
		Name:              matcherName,
		DisplayName:       "deps.dev License Matcher",
		MatchedPackages:   matchedPackages,
		UnmatchedPackages: unmatchedPackages,
		Licenses:          licenses,
	}
}

func (c *Checker) fetchBatch(ctx context.Context, items []pending, stats *checkStats) error {
	if len(items) == 0 {
		return nil
	}
	body := versionBatchRequest{Requests: make([]versionRequest, 0, len(items))}
	for _, item := range items {
		body.Requests = append(body.Requests, item.req)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("deps.dev: marshal batch request: %w", err)
	}

	endpoint := strings.TrimRight(c.config.APIBase, "/") + "/versionbatch"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("deps.dev: build batch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if stats != nil {
		stats.apiRequests++
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("deps.dev: execute batch request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("deps.dev: batch request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("deps.dev: read batch response: %w", err)
	}

	var batchResp versionBatchResponse
	if err := json.Unmarshal(rawBody, &batchResp); err != nil {
		return fmt.Errorf("deps.dev: decode batch response: %w", err)
	}
	enriched := 0
	for idx, result := range batchResp.Responses {
		if idx >= len(items) {
			break
		}
		values := licenseValuesFromResponse(result.Version)
		if err := cache.Set(c.cache, items[idx].key, values); err != nil {
			if stats != nil {
				stats.cacheWriteFailures++
			}
			c.logger.Warn("deps.dev: cache write failed", zap.Error(err))
		}
		if count := applyLicenses(items[idx].pkg, values); count > 0 {
			enriched++
			if stats != nil {
				stats.apiLicenses += count
			}
		}
	}
	if stats != nil {
		stats.apiEnriched += enriched
		if len(batchResp.Responses) < len(items) {
			stats.responseMisses += len(items) - len(batchResp.Responses)
		}
	}
	return nil
}

func applyLicenses(pkg *sdk.Package, values []string) int {
	if pkg == nil || len(pkg.Licenses) > 0 {
		return 0
	}
	normalized := matchers.NormalizeLicenseSet(values, SourceType)
	if len(normalized) == 0 {
		return 0
	}
	pkg.Licenses = normalized
	pkg.Matched = true
	return len(normalized)
}

func versionRequestFromPackage(pkg *sdk.Package) (versionRequest, cache.Key, bool) {
	if pkg == nil || strings.TrimSpace(pkg.Version) == "" {
		return versionRequest{}, cache.Key{}, false
	}
	if parsed, ok := parsePURL(strings.TrimSpace(pkg.PURL)); ok {
		if versionKey, ok := versionKeyFromParsedPURL(parsed); ok {
			return versionRequest{VersionKey: versionKey}, cache.NewKey(pkg.PURL, "", "", ""), true
		}
	}
	if versionKey, ok := versionKeyFromPackage(pkg); ok {
		return versionRequest{VersionKey: versionKey}, cache.NewKey("", pkg.Name, pkg.Ecosystem, pkg.Version), true
	}
	return versionRequest{}, cache.Key{}, false
}

func versionKeyFromPackage(pkg *sdk.Package) (versionKey, bool) {
	if pkg == nil {
		return versionKey{}, false
	}
	system, ok := depsDevSystem(pkg.Ecosystem)
	if !ok {
		return versionKey{}, false
	}
	name, ok := depsDevName(pkg)
	if !ok {
		return versionKey{}, false
	}
	return versionKey{System: system, Name: name, Version: pkg.Version}, true
}

func depsDevSystem(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "NPM", true
	case "maven":
		return "MAVEN", true
	case "go", "golang":
		return "GO", true
	case "python", "pypi":
		return "PYPI", true
	case "dotnet", "nuget":
		return "NUGET", true
	case "ruby", "rubygems":
		return "RUBYGEMS", true
	case "rust", "cargo":
		return "CARGO", true
	case "php", "composer":
		return "PACKAGIST", true
	case "elixir", "mix", "hex":
		return "HEXPM", true
	case "dart", "pub":
		return "PUB", true
	case "swift", "cocoapods":
		return "COCOAPODS", true
	default:
		return "", false
	}
}

func depsDevName(pkg *sdk.Package) (string, bool) {
	if pkg == nil {
		return "", false
	}
	name := strings.TrimSpace(pkg.Name)
	org := strings.TrimSpace(pkg.Org)
	switch strings.ToLower(strings.TrimSpace(pkg.Ecosystem)) {
	case "npm":
		if strings.HasPrefix(name, "@") {
			return name, true
		}
		if org != "" {
			if strings.HasPrefix(org, "@") {
				return org + "/" + name, true
			}
			return "@" + org + "/" + name, true
		}
		return name, name != ""
	case "maven":
		if org == "" || name == "" {
			return "", false
		}
		if strings.Contains(name, ":") {
			return org + ":" + strings.SplitN(name, ":", 2)[0], true
		}
		return org + ":" + name, true
	case "go", "golang":
		if org != "" {
			return strings.Trim(org, "/") + "/" + strings.Trim(name, "/"), true
		}
		return name, name != ""
	case "python", "pypi":
		return strings.ToLower(name), name != ""
	case "dotnet", "nuget":
		return strings.ToLower(name), name != ""
	case "php", "composer":
		if org != "" {
			return org + "/" + name, name != ""
		}
		return name, name != ""
	case "elixir", "mix", "hex":
		return strings.ToLower(name), name != ""
	default:
		return name, name != ""
	}
}

func licenseValuesFromResponse(version depsDevVersion) []string {
	if len(version.LicenseDetails) > 0 {
		values := make([]string, 0, len(version.LicenseDetails))
		for _, detail := range version.LicenseDetails {
			switch {
			case strings.TrimSpace(detail.SPDX) != "":
				values = append(values, detail.SPDX)
			case strings.TrimSpace(detail.License) != "":
				values = append(values, detail.License)
			}
		}
		if len(values) > 0 {
			return values
		}
	}
	return version.Licenses
}

type parsedPURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

func parsePURL(value string) (parsedPURL, bool) {
	if !strings.HasPrefix(value, "pkg:") {
		return parsedPURL{}, false
	}
	trimmed := strings.TrimPrefix(value, "pkg:")
	trimmed = strings.SplitN(trimmed, "#", 2)[0]
	trimmed = strings.SplitN(trimmed, "?", 2)[0]
	typeAndPath, version, hasVersion := strings.Cut(trimmed, "@")
	if !hasVersion {
		version = ""
	}
	typeValue, rawPath, ok := strings.Cut(typeAndPath, "/")
	if !ok {
		return parsedPURL{}, false
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		decodedPath = rawPath
	}
	parts := strings.Split(decodedPath, "/")
	if len(parts) == 0 {
		return parsedPURL{}, false
	}
	name := parts[len(parts)-1]
	namespace := ""
	if len(parts) > 1 {
		namespace = strings.Join(parts[:len(parts)-1], "/")
	}
	return parsedPURL{
		Type:      strings.ToLower(strings.TrimSpace(typeValue)),
		Namespace: strings.TrimSpace(namespace),
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(version),
	}, name != ""
}

func versionKeyFromParsedPURL(p parsedPURL) (versionKey, bool) {
	version := strings.TrimSpace(p.Version)
	if version == "" {
		return versionKey{}, false
	}
	switch p.Type {
	case "npm":
		name := p.Name
		if p.Namespace != "" {
			name = p.Namespace + "/" + p.Name
		}
		return versionKey{System: "NPM", Name: name, Version: version}, true
	case "maven":
		if p.Namespace == "" {
			return versionKey{}, false
		}
		return versionKey{System: "MAVEN", Name: p.Namespace + ":" + p.Name, Version: version}, true
	case "golang", "go":
		name := p.Name
		if p.Namespace != "" {
			name = path.Clean(p.Namespace + "/" + p.Name)
		}
		return versionKey{System: "GO", Name: name, Version: version}, true
	case "pypi":
		return versionKey{System: "PYPI", Name: strings.ToLower(p.Name), Version: version}, true
	case "nuget":
		return versionKey{System: "NUGET", Name: strings.ToLower(p.Name), Version: version}, true
	case "gem":
		return versionKey{System: "RUBYGEMS", Name: p.Name, Version: version}, true
	case "cargo":
		return versionKey{System: "CARGO", Name: p.Name, Version: version}, true
	case "composer":
		name := p.Name
		if p.Namespace != "" {
			name = p.Namespace + "/" + p.Name
		}
		return versionKey{System: "PACKAGIST", Name: name, Version: version}, true
	case "hex":
		return versionKey{System: "HEXPM", Name: strings.ToLower(p.Name), Version: version}, true
	case "pub":
		return versionKey{System: "PUB", Name: p.Name, Version: version}, true
	case "cocoapods":
		return versionKey{System: "COCOAPODS", Name: p.Name, Version: version}, true
	default:
		return versionKey{}, false
	}
}

type versionBatchRequest struct {
	Requests []versionRequest `json:"requests"`
}

type versionRequest struct {
	VersionKey versionKey `json:"versionKey"`
}

type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type versionBatchResponse struct {
	Responses []versionBatchResult `json:"responses"`
}

type versionBatchResult struct {
	Version depsDevVersion `json:"version"`
}

type depsDevVersion struct {
	Licenses       []string            `json:"licenses"`
	LicenseDetails []depsDevLicenseRef `json:"licenseDetails"`
}

type depsDevLicenseRef struct {
	License string `json:"license"`
	SPDX    string `json:"spdx"`
}
