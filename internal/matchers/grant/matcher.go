// Package grant implements a Matcher that shells out to the Anchore Grant CLI
// (https://github.com/anchore/grant) for license enrichment.
//
// Unlike syft/grype, this matcher does not have a builtin Go library variant.
// Grant's library blank-imports modernc.org/sqlite for syft RPM compatibility,
// which collides with the github.com/glebarez/go-sqlite driver pulled in by
// Bomly's builtin syft detector (both register database/sql driver name
// "sqlite" and panic at startup). The CLI shells out into its own process, so
// the collision does not happen there.
package grant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/matchers"
	audcache "github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	// MatcherName is the matcher registration name.
	MatcherName = "grant-license-checker"

	// SourceType identifies Grant license provenance in sdk.PackageLicense.Type.
	SourceType = "external-grant"

	binaryName = "grant"

	defaultCacheTTL = 24 * time.Hour
)

// Config configures the Grant license checker.
type Config struct {
	CacheDir string
	CacheTTL time.Duration
	Logger   *zap.Logger
}

// DefaultConfig returns a production-ready Grant checker config.
func DefaultConfig() Config {
	return Config{
		CacheDir: defaultCacheDir(),
		CacheTTL: defaultCacheTTL,
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bomly-cache", "licenses", "grant")
	}
	return filepath.Join(home, ".bomly", "cache", "licenses", "grant")
}

// Checker enriches package licenses using Anchore Grant.
type Checker struct {
	cache  *audcache.FileCache
	config Config
	logger *zap.Logger
}

type checkStats struct {
	requested          int
	cacheHits          int
	cacheMisses        int
	cacheApplied       int
	enriched           int
	notFound           int
	cacheWriteFailures int
	collectFailures    int
}

// New creates a Grant license checker.
func New(config Config) (*Checker, error) {
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if strings.TrimSpace(config.CacheDir) == "" {
		config.CacheDir = defaultCacheDir()
	}
	fileCache, err := audcache.NewFileCache(config.CacheDir, config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("grant checker: %w", err)
	}
	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Checker{
		cache:  fileCache,
		config: config,
		logger: logger,
	}, nil
}

// Descriptor returns the matcher registration metadata.
func (c *Checker) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:           MatcherName,
		Enabled:        true,
		Origin:         sdk.BundledOrigin,
		SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Priority:       85,
		Required:       false,
		Capabilities:   []string{"license-enrichment"},
	}
}

// Ready reports whether the external grant binary is available on PATH.
func (c *Checker) Ready() bool {
	_, err := exec.LookPath(binaryName)
	return err == nil
}

// Applicable reports whether the checker applies to the request.
func (c *Checker) Applicable(_ context.Context, req sdk.MatchRequest) (bool, error) {
	return req.Graph != nil, nil
}

// Match enriches missing package licenses by invoking the grant CLI.
func (c *Checker) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	if req.Graph == nil {
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}
	started := time.Now()
	packages := req.Graph.Packages()
	if req.Mode == sdk.TargetModeComponent && req.Target != nil {
		packages = []*sdk.Package{req.Target}
	}
	eligible := matchers.MissingLicensePackages(packages)
	stats := checkStats{requested: len(eligible)}
	if len(eligible) == 0 {
		c.logSummary(stats, time.Since(started))
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}

	type pending struct {
		pkg *sdk.Package
		key audcache.Key
	}
	var uncached []pending
	for _, pkg := range eligible {
		key := audcache.NewKey(pkg.PURL, pkg.Name, pkg.Ecosystem, pkg.Version)
		if cached, hit := audcache.Get[[]string](c.cache, key); hit {
			stats.cacheHits++
			if applyLicenses(pkg, cached) {
				stats.cacheApplied++
			}
			continue
		}
		stats.cacheMisses++
		uncached = append(uncached, pending{pkg: pkg, key: key})
	}

	if len(uncached) == 0 {
		c.logSummary(stats, time.Since(started))
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}

	results, err := c.collect(ctx, req.Graph)
	if err != nil {
		stats.collectFailures++
		c.logger.Warn("grant: license collection failed; skipping", zap.Error(err))
		c.logSummary(stats, time.Since(started))
		return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
	}

	for _, item := range uncached {
		licenses := lookupLicenses(results, item.pkg)
		if applyLicenses(item.pkg, licenses) {
			stats.enriched++
		} else if len(licenses) == 0 {
			stats.notFound++
		}
		if err := audcache.Set(c.cache, item.key, licenses); err != nil {
			stats.cacheWriteFailures++
			c.logger.Warn("grant: cache write failed", zap.Error(err))
		}
	}

	c.logSummary(stats, time.Since(started))
	return sdk.MatchResult{Graph: req.Graph, Target: req.Target}, nil
}

// collect serializes the dependency graph to SPDX JSON, pipes it through
// `grant list -o json -`, and returns a map keyed by (name, version) to the
// license expressions reported by Grant.
func (c *Checker) collect(_ context.Context, graph *sdk.Graph) (map[string][]string, error) {
	spdxBytes, err := sbom.MarshalDepGraphJSON(graph, sbom.TargetSPDX23JSON, sbom.BuildOptions{}, sbom.EncodeOptions{})
	if err != nil {
		return nil, fmt.Errorf("grant: serialize sbom: %w", err)
	}

	args := []string{"list", "-o", "json", "-"}
	var stdout, stderr bytes.Buffer
	cmd := system.Command(binaryName, args...)
	cmd.Stdin = bytes.NewReader(spdxBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	c.logger.Debug("grant: running CLI",
		zap.String("binary", binaryName),
		zap.Strings("args", args),
		zap.Int("sbom_bytes", len(spdxBytes)),
	)

	if err := cmd.Run(); err != nil {
		c.logger.Warn(fmt.Sprintf("grant CLI failed: %v (stderr: %s)", err, strings.TrimSpace(stderr.String())))
		return nil, fmt.Errorf("grant list failed: %w", err)
	}

	return parseGrantJSONOutput(stdout.Bytes())
}

func (c *Checker) logSummary(stats checkStats, elapsed time.Duration) {
	c.logger.Info(fmt.Sprintf("Grant license enrichment completed in %s", logging.FormatDuration(elapsed)),
		zap.Int("requested", stats.requested),
		zap.Int("enriched", stats.enriched),
		zap.Int("cache_hits", stats.cacheHits),
	)
	c.logger.Debug("grant: license check summary",
		zap.Int("requested", stats.requested),
		zap.Int("cache_hits", stats.cacheHits),
		zap.Int("cache_misses", stats.cacheMisses),
		zap.Int("cache_applied", stats.cacheApplied),
		zap.Int("enriched", stats.enriched),
		zap.Int("not_found", stats.notFound),
		zap.Int("cache_write_failures", stats.cacheWriteFailures),
		zap.Int("collect_failures", stats.collectFailures),
	)
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

// lookupKey is the matching key used between Grant results and graph packages.
// Grant's CLI output does not preserve PURLs, so we key on the lower-cased
// (name, version) pair.
func lookupKey(name, version string) string {
	return strings.ToLower(strings.TrimSpace(name)) + "@" + strings.TrimSpace(version)
}

func lookupLicenses(results map[string][]string, pkg *sdk.Package) []string {
	if pkg == nil {
		return nil
	}
	return results[lookupKey(pkg.Name, pkg.Version)]
}

type grantJSONOutput struct {
	Run struct {
		Targets []struct {
			Evaluation struct {
				Findings struct {
					Packages []struct {
						Name     string `json:"name"`
						Version  string `json:"version"`
						Licenses []struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"licenses"`
					} `json:"packages"`
				} `json:"findings"`
			} `json:"evaluation"`
		} `json:"targets"`
	} `json:"run"`
}

func parseGrantJSONOutput(data []byte) (map[string][]string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var out grantJSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode grant json: %w", err)
	}
	results := make(map[string][]string)
	for _, target := range out.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
			key := lookupKey(pkg.Name, pkg.Version)
			for _, license := range pkg.Licenses {
				value := strings.TrimSpace(license.ID)
				if value == "" {
					value = strings.TrimSpace(license.Name)
				}
				if value == "" {
					continue
				}
				results[key] = appendUnique(results[key], value)
			}
		}
	}
	return results, nil
}

func appendUnique(existing []string, value string) []string {
	for _, item := range existing {
		if item == value {
			return existing
		}
	}
	return append(existing, value)
}
