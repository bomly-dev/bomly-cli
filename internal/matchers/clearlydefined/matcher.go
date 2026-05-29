// Package clearlydefined implements a Bomly license checker backed by ClearlyDefined.
package clearlydefined

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/matchers"
	"github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	// SourceType identifies ClearlyDefined license provenance in sdk.PackageLicense.Type.
	SourceType = "external-clearlydefined"

	defaultAPIBase  = "https://api.clearlydefined.io"
	defaultCacheTTL = 24 * time.Hour
)

// Config configures the ClearlyDefined checker.
type Config struct {
	APIBase  string
	CacheDir string
	CacheTTL time.Duration
	Logger   *zap.Logger
	Client   *http.Client
}

// DefaultConfig returns a production-ready ClearlyDefined checker config.
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
		return filepath.Join(".bomly-cache", "licenses", "clearlydefined")
	}
	return filepath.Join(home, ".bomly", "cache", "licenses", "clearlydefined")
}

// Checker enriches package licenses from ClearlyDefined definitions.
type Checker struct {
	client *http.Client
	cache  *cache.FileCache
	config Config
	logger *zap.Logger
}

type checkStats struct {
	requested          int
	unsupported        int
	cacheHits          int
	cacheMisses        int
	cacheApplied       int
	apiRequests        int
	apiEnriched        int
	cacheWriteFailures int
	notFound           int
}

// New creates a ClearlyDefined checker.
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
		return nil, fmt.Errorf("clearlydefined checker: %w", err)
	}
	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	client := config.Client
	if client == nil {
		client, err = sdk.NewHTTPClient(sdk.HTTPClientConfig{Timeout: 20 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("clearlydefined checker: create HTTP client: %w", err)
		}
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
		Name:           "clearlydefined-license-checker",
		Enabled:        false,
		Origin:         sdk.CoreOrigin,
		SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Priority:       90,
		Required:       false,
		Capabilities:   []string{"license-enrichment", "http"},
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

// Match enriches missing package licenses via ClearlyDefined.
func (c *Checker) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	if req.Graph == nil {
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}
	packages := req.Graph.Packages()
	if req.Mode == sdk.TargetModeComponent && req.Target != nil {
		packages = []*sdk.Package{req.Target}
	}
	eligible := matchers.MissingLicensePackages(packages)
	stats := checkStats{requested: len(eligible)}
	for _, pkg := range eligible {
		coordinate, cacheKey, ok := coordinateFromPackage(pkg)
		if !ok {
			stats.unsupported++
			continue
		}
		if cached, hit := cache.Get[[]string](c.cache, cacheKey); hit {
			stats.cacheHits++
			if applyLicenses(pkg, cached) {
				stats.cacheApplied++
			}
			continue
		}
		stats.cacheMisses++
		stats.apiRequests++
		values, err := c.fetchDefinition(ctx, coordinate)
		if err != nil {
			return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, err
		}
		if len(values) == 0 {
			stats.notFound++
		}
		if err := cache.Set(c.cache, cacheKey, values); err != nil {
			stats.cacheWriteFailures++
			c.logger.Warn("clearlydefined: cache write failed", zap.Error(err))
		}
		if applyLicenses(pkg, values) {
			stats.apiEnriched++
		}
	}
	c.logger.Debug(
		"clearlydefined: license check summary",
		zap.Int("requested", stats.requested),
		zap.Int("cache_hits", stats.cacheHits),
		zap.Int("cache_misses", stats.cacheMisses),
		zap.Int("cache_applied", stats.cacheApplied),
		zap.Int("api_requests", stats.apiRequests),
		zap.Int("api_enriched", stats.apiEnriched),
		zap.Int("not_found", stats.notFound),
		zap.Int("cache_write_failures", stats.cacheWriteFailures),
		zap.Int("unsupported", stats.unsupported),
	)
	return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
}

func (c *Checker) fetchDefinition(ctx context.Context, coordinate string) ([]string, error) {
	endpoint := strings.TrimRight(c.config.APIBase, "/") + "/definitions/" + coordinate
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("clearlydefined: build request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clearlydefined: execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("clearlydefined: request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var definition response
	if err := json.NewDecoder(resp.Body).Decode(&definition); err != nil {
		return nil, fmt.Errorf("clearlydefined: decode response: %w", err)
	}
	return definition.licenseValues(), nil
}

func applyLicenses(pkg *sdk.Package, values []string) bool {
	if pkg == nil || len(pkg.Licenses) > 0 {
		return false
	}
	normalized := matchers.NormalizeLicenseSet(values, SourceType)
	if len(normalized) == 0 {
		return false
	}
	pkg.Licenses = normalized
	pkg.Matched = true
	return true
}

func coordinateFromPackage(pkg *sdk.Package) (string, cache.Key, bool) {
	if pkg == nil || strings.TrimSpace(pkg.Version) == "" {
		return "", cache.Key{}, false
	}
	if parsed, ok := parsePURL(strings.TrimSpace(pkg.PURL)); ok {
		if coordinate, ok := coordinateFromParsedPURL(parsed); ok {
			return coordinate, cache.NewKey(pkg.PURL, "", "", ""), true
		}
	}
	if coordinate, ok := coordinateFromGraphPackage(pkg); ok {
		return coordinate, cache.NewKey("", pkg.Name, pkg.Ecosystem, pkg.Version), true
	}
	return "", cache.Key{}, false
}

func coordinateFromGraphPackage(pkg *sdk.Package) (string, bool) {
	if pkg == nil {
		return "", false
	}
	name := strings.TrimSpace(pkg.Name)
	org := strings.TrimSpace(pkg.Org)
	version := strings.TrimSpace(pkg.Version)
	switch strings.ToLower(strings.TrimSpace(pkg.Ecosystem)) {
	case "php":
		if name == "" {
			return "", false
		}
		namespace := org
		if namespace == "" {
			namespace = "-"
		}
		return "composer/packagist/" + escapeSegment(namespace) + "/" + escapeSegment(name) + "/" + escapeSegment(version), true
	case "dpkg":
		if name == "" {
			return "", false
		}
		return "deb/debian/-/" + escapeSegment(name) + "/" + escapeSegment(version), true
	case "swift":
		if name == "" {
			return "", false
		}
		return "pod/cocoapods/-/" + escapeSegment(name) + "/" + escapeSegment(version), true
	default:
		return "", false
	}
}

type parsedPURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

func parsePURL(value string) (parsedPURL, bool) {
	if !strings.HasPrefix(value, "pkg:") {
		return parsedPURL{}, false
	}
	trimmed := strings.TrimPrefix(value, "pkg:")
	trimmed = strings.SplitN(trimmed, "#", 2)[0]
	typeAndPath := trimmed
	qualifierText := ""
	if base, qualifiers, ok := strings.Cut(trimmed, "?"); ok {
		typeAndPath = base
		qualifierText = qualifiers
	}
	typeAndPath, version, _ := strings.Cut(typeAndPath, "@")
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
	qualifiers := make(map[string]string)
	for _, part := range strings.Split(qualifierText, "&") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		decodedVal, err := url.QueryUnescape(val)
		if err != nil {
			decodedVal = val
		}
		qualifiers[strings.ToLower(strings.TrimSpace(key))] = decodedVal
	}
	name := parts[len(parts)-1]
	namespace := ""
	if len(parts) > 1 {
		namespace = strings.Join(parts[:len(parts)-1], "/")
	}
	return parsedPURL{
		Type:       strings.ToLower(strings.TrimSpace(typeValue)),
		Namespace:  strings.TrimSpace(namespace),
		Name:       strings.TrimSpace(name),
		Version:    strings.TrimSpace(version),
		Qualifiers: qualifiers,
	}, name != ""
}

func coordinateFromParsedPURL(p parsedPURL) (string, bool) {
	if p.Version == "" {
		return "", false
	}
	switch p.Type {
	case "composer":
		namespace := p.Namespace
		if namespace == "" {
			namespace = "-"
		}
		return "composer/packagist/" + escapeSegment(namespace) + "/" + escapeSegment(p.Name) + "/" + escapeSegment(p.Version), true
	case "deb":
		return "deb/debian/-/" + escapeSegment(p.Name) + "/" + escapeSegment(p.Version), true
	case "cocoapods":
		return "pod/cocoapods/-/" + escapeSegment(p.Name) + "/" + escapeSegment(p.Version), true
	case "conda":
		channel := strings.TrimSpace(p.Qualifiers["channel"])
		subdir := strings.TrimSpace(p.Qualifiers["subdir"])
		if channel == "" || subdir == "" {
			return "", false
		}
		provider := condaProvider(channel)
		if provider == "" {
			return "", false
		}
		return "conda/" + escapeSegment(provider) + "/" + escapeSegment(subdir) + "/" + escapeSegment(p.Name) + "/" + escapeSegment(p.Version), true
	default:
		return "", false
	}
}

func condaProvider(channel string) string {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "main":
		return "anaconda-main"
	case "r":
		return "anaconda-r"
	case "conda-forge":
		return "conda-forge"
	default:
		return ""
	}
}

func escapeSegment(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return url.PathEscape(strings.TrimSpace(value))
}

type response struct {
	Licensed licensed `json:"licensed"`
}

type licensed struct {
	Declared string `json:"declared"`
	Facets   struct {
		Core struct {
			Discovered struct {
				Expressions []string `json:"expressions"`
			} `json:"discovered"`
		} `json:"core"`
	} `json:"facets"`
}

func (r response) licenseValues() []string {
	if strings.TrimSpace(r.Licensed.Declared) != "" {
		return []string{strings.TrimSpace(r.Licensed.Declared)}
	}
	return r.Licensed.Facets.Core.Discovered.Expressions
}
