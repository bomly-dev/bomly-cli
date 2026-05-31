package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/matchers"
	matchercache "github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	statusSupported      = "supported"
	statusSecurityOnly   = "security-only"
	statusApproachingEOL = "approaching-eol"
	statusEndOfLife      = "end-of-life"
	statusUnknown        = "unknown"

	metadataEOLKey = "endoflife.date"

	// matcherName labels this matcher in MatchResult.MatcherRuns.
	matcherName = "eol"

	defaultAPIBase  = "https://endoflife.date/api"
	defaultCacheTTL = 24 * time.Hour

	approachingWindowDays = 180
)

// Config configures the EOL enrichment matcher.
type Config struct {
	APIBase  string
	CacheDir string
	CacheTTL time.Duration
	Timeout  time.Duration
	Logger   *zap.Logger
	Client   *http.Client
}

// DefaultConfig returns a production-ready EOL checker config.
func DefaultConfig() Config {
	return Config{
		APIBase:  defaultAPIBase,
		CacheDir: defaultCacheDir(),
		CacheTTL: defaultCacheTTL,
		Timeout:  15 * time.Second,
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "eol")
	}
	return filepath.Join(home, ".bomly", "cache", "eol")
}

// Checker enriches package metadata with end-of-life status.
type Checker struct {
	client *http.Client
	cache  *matchercache.FileCache
	config Config
	logger *zap.Logger
}

// New creates an EOL enrichment matcher.
func New(config Config) (*Checker, error) {
	if strings.TrimSpace(config.APIBase) == "" {
		config.APIBase = defaultAPIBase
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	if strings.TrimSpace(config.CacheDir) == "" {
		config.CacheDir = defaultCacheDir()
	}
	cache, err := matchercache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("eol checker: %w", err)
	}
	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}

	return &Checker{
		client: client,
		cache:  cache,
		config: config,
		logger: logger,
	}, nil
}

// Descriptor returns matcher registration metadata.
func (c *Checker) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:           "eol-checker",
		Enabled:        false,
		Origin:         sdk.CoreOrigin,
		SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Priority:       80,
		Required:       false,
		Capabilities:   []string{"eol-enrichment", "http-cache"},
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

// Match enriches packages with EOL status metadata.
func (c *Checker) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	if req.Graph == nil || req.Registry == nil {
		c.logger.Debug("eol: skipped because graph or registry is nil")
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, nil
	}

	packages := matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Mode, req.Target)
	c.logger.Info("eol: matcher invoked", zap.String("mode", string(req.Mode)), zap.Int("packages", len(packages)))

	products, err := c.fetchProducts(ctx)
	if err != nil {
		c.logger.Warn("eol: failed to fetch products", zap.Error(err))
		return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, err
	}

	enrichedCount := 0
	mappedCount := 0
	cycleErrorCount := 0

	for _, pkg := range packages {
		if pkg == nil || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		product, ok := resolveProduct(pkg, products)
		if !ok {
			continue
		}
		mappedCount++
		cycles, err := c.fetchCycles(ctx, product)
		if err != nil {
			cycleErrorCount++
			c.logger.Debug("eol: fetch cycles failed", zap.String("product", product), zap.Error(err))
			continue
		}
		entry := classifyEOL(product, strings.TrimSpace(pkg.Version), cycles, time.Now().UTC())
		if entry == nil {
			continue
		}
		if pkg.Metadata == nil {
			pkg.Metadata = make(map[string]any, 1)
		}
		pkg.Metadata[metadataEOLKey] = entry
		enrichedCount++
	}
	c.logger.Info("eol: matcher completed",
		zap.Int("packages", len(packages)),
		zap.Int("mapped_products", mappedCount),
		zap.Int("enriched_packages", enrichedCount),
		zap.Int("cycle_errors", cycleErrorCount),
	)

	return sdk.MatchResult{Registry: req.Registry, MatcherRuns: []string{matcherName}}, nil
}

type dateOrBool struct {
	Date string
	Bool *bool
}

func (d *dateOrBool) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		d.Date = ""
		d.Bool = nil
		return nil
	}
	if trimmed == "true" || trimmed == "false" {
		value := trimmed == "true"
		d.Bool = &value
		d.Date = ""
		return nil
	}
	var asString string
	if err := json.Unmarshal(data, &asString); err != nil {
		return err
	}
	d.Date = strings.TrimSpace(asString)
	d.Bool = nil
	return nil
}

func (d *dateOrBool) reached(now time.Time) bool {
	if d.Bool != nil {
		return *d.Bool
	}
	if strings.TrimSpace(d.Date) == "" {
		return false
	}
	date, err := time.Parse("2006-01-02", d.Date)
	if err != nil {
		return false
	}
	return !date.After(now)
}

type productCycle struct {
	Cycle   string      `json:"cycle"`
	EOL     dateOrBool  `json:"eol"`
	Support *dateOrBool `json:"support,omitempty"`
	LTS     *dateOrBool `json:"lts,omitempty"`
}

func (c *Checker) fetchProducts(ctx context.Context) (map[string]struct{}, error) {
	key := matchercache.NewKey("eol", "products", "", "")
	if cached, ok := matchercache.Get[[]string](c.cache, key); ok {
		set := make(map[string]struct{}, len(cached))
		for _, item := range cached {
			set[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
		}
		return set, nil
	}

	endpoint := strings.TrimRight(c.config.APIBase, "/") + "/all.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("eol: build product list request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eol: fetch product list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("eol: product list request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var products []string
	if err := json.NewDecoder(resp.Body).Decode(&products); err != nil {
		return nil, fmt.Errorf("eol: decode product list: %w", err)
	}
	_ = matchercache.Set(c.cache, key, products)
	set := make(map[string]struct{}, len(products))
	for _, item := range products {
		set[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
	}
	return set, nil
}

func (c *Checker) fetchCycles(ctx context.Context, product string) ([]productCycle, error) {
	key := matchercache.NewKey("eol", product, "", "")
	if cached, ok := matchercache.Get[[]productCycle](c.cache, key); ok {
		return cached, nil
	}

	endpoint := strings.TrimRight(c.config.APIBase, "/") + "/" + url.PathEscape(product) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("eol: build cycle request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eol: fetch cycles for %s: %w", product, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("eol: cycle request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var cycles []productCycle
	if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
		return nil, fmt.Errorf("eol: decode cycles for %s: %w", product, err)
	}
	_ = matchercache.Set(c.cache, key, cycles)
	return cycles, nil
}

func resolveProduct(pkg *sdk.Package, products map[string]struct{}) (string, bool) {
	if pkg == nil || len(products) == 0 {
		return "", false
	}
	eco := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	name := strings.ToLower(strings.TrimSpace(pkg.Name))
	org := strings.ToLower(strings.TrimSpace(pkg.Org))

	candidates := make([]string, 0, 4)
	switch eco {
	case "npm":
		if org == "angular" && name == "core" {
			candidates = append(candidates, "angular")
		}
		candidates = append(candidates, name)
	case "python":
		candidates = append(candidates, strings.ReplaceAll(name, "_", "-"), name)
	case "go", "golang":
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 0 {
			candidates = append(candidates, parts[len(parts)-1])
		}
	case "maven":
		if org == "org.springframework.boot" && name == "spring-boot" {
			candidates = append(candidates, "spring-boot")
		}
		candidates = append(candidates, name)
	default:
		candidates = append(candidates, name)
	}

	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if _, ok := products[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

func classifyEOL(product, version string, cycles []productCycle, now time.Time) map[string]any {
	cycle, ok := matchCycle(version, cycles)
	if !ok {
		return map[string]any{
			"product": product,
			"status":  statusUnknown,
		}
	}

	status := statusSupported
	result := map[string]any{
		"product": product,
		"cycle":   cycle.Cycle,
	}

	eolReached := cycle.EOL.reached(now)
	if eolReached {
		status = statusEndOfLife
	} else if cycle.Support != nil && cycle.Support.reached(now) {
		status = statusSecurityOnly
	} else if strings.TrimSpace(cycle.EOL.Date) != "" {
		eolDate, err := time.Parse("2006-01-02", cycle.EOL.Date)
		if err == nil {
			days := int(eolDate.Sub(now).Hours() / 24)
			result["eol_date"] = cycle.EOL.Date
			result["days_until_eol"] = days
			if days >= 0 && days <= approachingWindowDays {
				status = statusApproachingEOL
			}
		}
	}

	result["status"] = status
	return result
}

func matchCycle(version string, cycles []productCycle) (productCycle, bool) {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if version == "" || len(cycles) == 0 {
		return productCycle{}, false
	}

	for _, candidate := range cycleCandidates(version) {
		for _, cycle := range cycles {
			if strings.EqualFold(strings.TrimSpace(cycle.Cycle), candidate) {
				return cycle, true
			}
		}
	}
	return productCycle{}, false
}

func cycleCandidates(version string) []string {
	trimmed := strings.TrimSpace(version)
	parts := strings.Split(trimmed, ".")
	major := numericPrefix(parts[0])
	if major == "" {
		return []string{trimmed}
	}
	candidates := make([]string, 0, 3)
	candidates = append(candidates, trimmed)
	if len(parts) > 1 {
		minor := numericPrefix(parts[1])
		if minor != "" {
			candidates = append(candidates, major+"."+minor)
		}
	}
	candidates = append(candidates, major)
	return uniqueCandidates(candidates)
}

func numericPrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return ""
	}
	if _, err := strconv.Atoi(b.String()); err != nil {
		return ""
	}
	return b.String()
}

func uniqueCandidates(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
