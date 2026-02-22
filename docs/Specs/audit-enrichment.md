# Audit Enrichment Spec — `bomly scan --audit`

**Status:** Ready for agentic implementation  
**Date:** 2026-04-13  
**Implements:** ADR-007  
**Target:** bomly-cli

---

## 1. Overview

This spec defines all changes required to implement the enrichment and analysis features attached to `bomly scan --audit` and extended `bomly diff`. The scope covers:

- OSV vulnerability enrichment with CISA KEV flagging
- VEX overlay support (CycloneDX VEX format) to suppress false positives and annotate findings
- License visibility in all scan output, including undeclared-license findings when `--audit` is set
- SARIF 2.1.0 output format for direct GitHub Security tab integration
- SBOM-to-SBOM diffing via Syft (`bomly diff --base-sbom / --head-sbom`)

License policy evaluation (allow/deny/review lists, copyleft propagation) and SBOM quality scoring (NTIA, CRA, FDA, NIST) are **out of scope for the CLI** and are planned as paid features in Bomly's SBOM management portal.

The implementation requires no new third-party Go dependencies beyond what is already in `go.mod`.

Logging for enrichment work should stay concise: prefer compact one-line messages when only one or two values matter, use structured fields for multi-field summaries, and log cache/API activity as aggregated operation summaries rather than per-package hit/miss/request chatter unless a warning needs item-level detail.

---

## 2. Files to create

```
internal/enrichment/
  cache.go
  vex/
    reader.go
    applier.go

internal/auditors/osv/
  client.go
  response.go
  mapper.go
  kev.go
  auditor.go
  auditor_test.go

internal/auditors/grype/
  auditor.go
  auditor_test.go

internal/output/
  sarif.go
  sarif_test.go
```

## 3. Files to modify

```
internal/scan/types.go           — add VexStatus string field to Finding; add AuditorFilter type; add AuditorFilter to AuditRequest
internal/scan/registry.go        — add AuditorDescriptors() method; apply AuditorFilter name-based filtering in Auditors()
internal/graph/graph.go          — no change required (PURL, Licenses already present)
internal/output/output.go        — add structured Licenses []LicenseRef to PackageRef
internal/cli/options.go          — add Auditors string and ExcludeAuditors string fields; bind --auditors / --exclude-auditors persistent root flags
internal/cli/flag_options.go     — add availableAuditorOptions(); register --auditors / --exclude-auditors completions in bindDynamicFlagOptions()
internal/cli/resolver.go         — register grype.Auditor in buildScanRegistry(); remove noop registrations when --audit flag is set (or keep noop at priority 10 as fallback — see §20)
internal/cli/scan_cmd.go         — --audit, --vex (repeatable), --fail-on, --format sarif flags; audit block; VEX applier; SARIF output; pass AuditorFilter to AuditRequest
internal/cli/diff_cmd.go         — --base-sbom / --head-sbom flags; resolveSBOMDiffGraphs()
docs/Specs/v1.0.md               — update scan and diff command sections
docs/ADRs/README.md              — register ADR-007
```

---

## 4. Package: `internal/enrichment`

### 4.1 `internal/enrichment/cache.go`

Implements a file-based cache for OSV query results.

```go
package enrichment

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"
)

// CacheKey uniquely identifies one OSV query result.
type CacheKey struct {
    raw string
}

// NewCacheKey creates a stable cache key from the given fields.
// Up to the caller to pass the most specific identity available (PURL preferred).
func NewCacheKey(purl, name, ecosystem, version string) CacheKey {
    raw := fmt.Sprintf("%s|%s|%s|%s", purl, name, ecosystem, version)
    sum := sha256.Sum256([]byte(raw))
    return CacheKey{raw: hex.EncodeToString(sum[:])}
}

// FileCache stores JSON-encoded values on disk with a TTL.
type FileCache struct {
    dir string
    ttl time.Duration
}

type cacheEntry[T any] struct {
    CachedAt time.Time `json:"cached_at"`
    Value    T         `json:"value"`
}

// NewFileCache creates a cache rooted at dir with the specified TTL.
// dir is created if it does not exist.
func NewFileCache(dir string, ttl time.Duration) (*FileCache, error) {
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return nil, fmt.Errorf("create cache dir: %w", err)
    }
    return &FileCache{dir: dir, ttl: ttl}, nil
}

func (c *FileCache) path(key CacheKey) string {
    return filepath.Join(c.dir, key.raw+".json")
}

// Get returns the cached value for key if it exists and has not expired.
// Returns (zero, false) on miss or expiry.
func Get[T any](c *FileCache, key CacheKey) (T, bool) {
    var zero T
    data, err := os.ReadFile(c.path(key))
    if err != nil {
        return zero, false
    }
    var entry cacheEntry[T]
    if err := json.Unmarshal(data, &entry); err != nil {
        return zero, false
    }
    if time.Since(entry.CachedAt) > c.ttl {
        return zero, false
    }
    return entry.Value, true
}

// Set writes value to the cache under key.
func Set[T any](c *FileCache, key CacheKey, value T) error {
    entry := cacheEntry[T]{CachedAt: time.Now(), Value: value}
    data, err := json.Marshal(entry)
    if err != nil {
        return fmt.Errorf("marshal cache entry: %w", err)
    }
    return os.WriteFile(c.path(key), data, 0o600)
}
```

**Notes:**
- Generic functions `Get[T]` and `Set[T]` require Go 1.21+. The module is on Go 1.22, so this is valid.
- File permissions are `0o700` for directory (owner-only) and `0o600` for files (owner read/write). No secrets are stored, but vulnerability data may be considered sensitive context.
- Do not store PURLs in the filename (may contain special characters); the SHA-256 hex is the filename.

---

## 5. Package: `internal/auditors/osv`

### 5.1 `internal/auditors/osv/response.go`

OSV API request and response types.

```go
package osv

import "encoding/json"

// BatchRequest is the body sent to /v1/querybatch.
type BatchRequest struct {
    Queries []Query `json:"queries"`
}

// Query is one entry in a batch request.
// Exactly one of Purl or Package must be set.
type Query struct {
    // PurlQuery sends a PURL-based query.
    Purl    *PurlQuery    `json:"package,omitempty"`
    // PackageQuery sends a name+ecosystem+version query.
    Package *PackageQuery `json:"package,omitempty"`
    Version string        `json:"version,omitempty"`
}
```

> **Note:** The OSV batch API uses the same `package` key for both PURL-based and name-based queries, distinguished by whether `purl` or `name`+`ecosystem` is set inside the object. Define two concrete wire types and use an interface or separate fields to build the right JSON:

```go
// Wire types — used only for serialisation.

// PurlPackage is the wire shape for PURL-based queries.
type PurlPackage struct {
    Purl string `json:"purl"`
}

// NamePackage is the wire shape for name+ecosystem queries.
type NamePackage struct {
    Name      string `json:"name"`
    Ecosystem string `json:"ecosystem"`
}

// BatchQuery is one entry in the OSV batch request wire format.
// Exactly one of PurlPkg or NamePkg will be set.
type BatchQuery struct {
    Package json.RawMessage `json:"package"`
    Version string          `json:"version,omitempty"`
}

// BatchRequest is the wire body for POST /v1/querybatch.
type BatchRequest struct {
    Queries []BatchQuery `json:"queries"`
}

// BatchResponse is the top-level response from POST /v1/querybatch.
type BatchResponse struct {
    Results []BatchResult `json:"results"`
}

// BatchResult is the result for one query in the batch.
type BatchResult struct {
    Vulns []OsvVulnerability `json:"vulns"`
}

// OsvVulnerability is a single vulnerability entry from OSV.
type OsvVulnerability struct {
    ID       string        `json:"id"`
    Summary  string        `json:"summary"`
    Details  string        `json:"details"`
    Aliases  []string      `json:"aliases"`
    Severity []OsvSeverity `json:"severity"`
    Affected []OsvAffected `json:"affected"`
    Published string       `json:"published"`
    Modified  string       `json:"modified"`
    DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

// OsvSeverity holds a CVSS vector and type.
type OsvSeverity struct {
    Type  string `json:"type"`   // e.g. "CVSS_V3", "CVSS_V4"
    Score string `json:"score"`  // vector string or numeric score
}

// OsvAffected holds version ranges and specific affected versions.
type OsvAffected struct {
    Versions []string    `json:"versions"`
    Ranges   []OsvRange  `json:"ranges"`
}

// OsvRange holds a single range entry.
type OsvRange struct {
    Events []OsvEvent `json:"events"`
}

// OsvEvent holds introduced/fixed/last_affected markers.
type OsvEvent struct {
    Introduced  string `json:"introduced,omitempty"`
    Fixed       string `json:"fixed,omitempty"`
    LastAffected string `json:"last_affected,omitempty"`
}

// DatabaseSpecific holds ecosystem-specific metadata (e.g. CWE IDs from GitHub).
type DatabaseSpecific struct {
    CweIDs []string `json:"cwe_ids,omitempty"`
}
```

### 5.2 `internal/auditors/osv/client.go`

HTTP client for the OSV API. Uses `net/http` only.

```go
package osv

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

const (
    defaultAPIBase   = "https://api.osv.dev"
    defaultTimeout   = 30 * time.Second
    defaultBatchSize = 1000
    maxRetries       = 3
)

// ClientConfig configures the OSV HTTP client.
type ClientConfig struct {
    APIBase   string
    Timeout   time.Duration
    BatchSize int
}

// DefaultClientConfig returns a production-ready default config.
func DefaultClientConfig() ClientConfig {
    return ClientConfig{
        APIBase:   defaultAPIBase,
        Timeout:   defaultTimeout,
        BatchSize: defaultBatchSize,
    }
}

// Client is an HTTP client for the OSV batch API.
type Client struct {
    http      *http.Client
    config    ClientConfig
}

// NewClient creates a new OSV client.
func NewClient(config ClientConfig) *Client {
    if config.APIBase == "" {
        config.APIBase = defaultAPIBase
    }
    if config.Timeout == 0 {
        config.Timeout = defaultTimeout
    }
    if config.BatchSize == 0 {
        config.BatchSize = defaultBatchSize
    }
    return &Client{
        http:   &http.Client{Timeout: config.Timeout},
        config: config,
    }
}

// QueryBatch sends a batch of queries to OSV and returns one result per query.
// Automatically splits queries into chunks of config.BatchSize.
func (c *Client) QueryBatch(queries []BatchQuery) ([]BatchResult, error) {
    if len(queries) == 0 {
        return nil, nil
    }

    var all []BatchResult
    for i := 0; i < len(queries); i += c.config.BatchSize {
        end := i + c.config.BatchSize
        if end > len(queries) {
            end = len(queries)
        }
        results, err := c.queryChunk(queries[i:end])
        if err != nil {
            return nil, err
        }
        all = append(all, results...)
    }
    return all, nil
}

func (c *Client) queryChunk(queries []BatchQuery) ([]BatchResult, error) {
    body, err := json.Marshal(BatchRequest{Queries: queries})
    if err != nil {
        return nil, fmt.Errorf("marshal osv batch request: %w", err)
    }

    url := c.config.APIBase + "/v1/querybatch"

    var last error
    for attempt := 0; attempt < maxRetries; attempt++ {
        resp, err := c.http.Post(url, "application/json", bytes.NewReader(body)) // #nosec G107 — URL is from config, not user input
        if err != nil {
            last = fmt.Errorf("osv request attempt %d: %w", attempt+1, err)
            continue
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            last = fmt.Errorf("osv api returned status %d", resp.StatusCode)
            continue
        }

        data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB limit
        if err != nil {
            last = fmt.Errorf("osv read response: %w", err)
            continue
        }

        var batch BatchResponse
        if err := json.Unmarshal(data, &batch); err != nil {
            return nil, fmt.Errorf("osv unmarshal response: %w", err)
        }
        return batch.Results, nil
    }
    return nil, last
}
```

**Security notes:**
- `io.LimitReader(resp.Body, 64<<20)` caps response body at 64 MB to prevent memory exhaustion on malformed responses (defense against CWE-400).
- `#nosec G107` annotation documents the intentional use of a configurable URL (set from code defaults, not user input at runtime).

### 5.3 `internal/auditors/osv/mapper.go`

Maps `OsvVulnerability` → `scan.Finding`.

```go
package osv

import (
    "fmt"
    "strconv"
    "strings"

    "github.com/bomly/bomly-cli/internal/graph"
    "github.com/bomly/bomly-cli/internal/scan"
)

// MapVulnerability converts one OsvVulnerability into a scan.Finding.
func MapVulnerability(v OsvVulnerability, pkg *graph.Package) scan.Finding {
    return scan.Finding{
        ID:       v.ID,
        Kind:     scan.FindingKindVulnerability,
        Package:  pkg,
        Title:    firstNonEmpty(v.Summary, v.ID),
        Severity: extractSeverity(v.Severity),
        Reasons:  buildReasons(v),
        Source:   "osv",
    }
}

func firstNonEmpty(a, b string) string {
    if a != "" {
        return a
    }
    return b
}

// extractSeverity derives a normalized severity string from OSV severity entries.
// Prefers CVSS v4 > v3.1 > v3 > v2 > unknown.
func extractSeverity(severities []OsvSeverity) string {
    scores := map[string]float64{}
    for _, s := range severities {
        if score := parseCVSSScore(s.Score); score > 0 {
            scores[s.Type] = score
        }
    }
    // Priority order
    for _, t := range []string{"CVSS_V4", "CVSS_V31", "CVSS_V3", "CVSS_V2"} {
        if score, ok := scores[t]; ok {
            return cvssScoreToBand(score)
        }
    }
    return "unknown"
}

func parseCVSSScore(raw string) float64 {
    f, err := strconv.ParseFloat(raw, 64)
    if err == nil {
        return f
    }
    // Vector string: CVSS:3.1/AV:N/.../score:9.8 is not standard.
    // Try the last segment after all slashes.
    parts := strings.Split(raw, "/")
    if len(parts) > 0 {
        if f, err := strconv.ParseFloat(parts[len(parts)-1], 64); err == nil {
            return f
        }
    }
    return 0
}

func cvssScoreToBand(score float64) string {
    switch {
    case score >= 9.0:
        return "critical"
    case score >= 7.0:
        return "high"
    case score >= 4.0:
        return "medium"
    default:
        return "low"
    }
}

func buildReasons(v OsvVulnerability) []string {
    var reasons []string
    if fixed := extractFixedVersion(v.Affected); fixed != "" {
        reasons = append(reasons, fmt.Sprintf("Fix available: upgrade to %s", fixed))
    }
    if len(v.Aliases) > 0 {
        reasons = append(reasons, fmt.Sprintf("Also known as: %s", strings.Join(v.Aliases, ", ")))
    }
    if cwes := extractCWEs(v.DatabaseSpecific); len(cwes) > 0 {
        reasons = append(reasons, fmt.Sprintf("CWEs: %s", strings.Join(cwes, ", ")))
    }
    return reasons
}

func extractFixedVersion(affected []OsvAffected) string {
    for _, a := range affected {
        for _, r := range a.Ranges {
            for _, e := range r.Events {
                if e.Fixed != "" {
                    return e.Fixed
                }
            }
        }
    }
    return ""
}

func extractCWEs(ds *DatabaseSpecific) []string {
    if ds == nil {
        return nil
    }
    return ds.CweIDs
}
```

### 5.4 `internal/auditors/osv/kev.go`

Downloads and parses the CISA KEV catalog.

```go
package osv

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

const (
    kevURL            = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kevFetchTimeout   = 15 * time.Second
)

// KEVCatalog is the in-memory representation of the CISA KEV catalog.
type KEVCatalog struct {
    ids map[string]struct{}
}

type kevResponse struct {
    Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
    CveID string `json:"cveID"`
}

// FetchKEVCatalog downloads the CISA KEV catalog.
// Returns (nil, nil) if the request fails — callers treat absence as informational.
func FetchKEVCatalog() (*KEVCatalog, error) {
    client := &http.Client{Timeout: kevFetchTimeout}
    resp, err := client.Get(kevURL) // #nosec G107 — constant URL
    if err != nil {
        return nil, fmt.Errorf("fetch kev catalog: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("kev catalog returned status %d", resp.StatusCode)
    }

    data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MB limit
    if err != nil {
        return nil, fmt.Errorf("read kev catalog: %w", err)
    }

    var result kevResponse
    if err := json.Unmarshal(data, &result); err != nil {
        return nil, fmt.Errorf("parse kev catalog: %w", err)
    }

    catalog := &KEVCatalog{ids: make(map[string]struct{}, len(result.Vulnerabilities))}
    for _, v := range result.Vulnerabilities {
        catalog.ids[v.CveID] = struct{}{}
    }
    return catalog, nil
}

// Contains reports whether id (or any alias) is in the KEV catalog.
func (k *KEVCatalog) Contains(id string, aliases []string) bool {
    if _, ok := k.ids[id]; ok {
        return true
    }
    for _, alias := range aliases {
        if _, ok := k.ids[alias]; ok {
            return true
        }
    }
    return false
}
```

### 5.5 `internal/auditors/osv/auditor.go`

Implements `scan.Auditor`.

```go
package osv

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/bomly/bomly-cli/internal/enrichment"
    "github.com/bomly/bomly-cli/internal/graph"
    "github.com/bomly/bomly-cli/internal/scan"
)

const (
    defaultCacheTTL = 24 * time.Hour
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
    // Stderr is used for progress messages. May be nil.
    Stderr io.Writer
}

// DefaultConfig returns a production-ready OSV auditor config.
func DefaultConfig() Config {
    return Config{
        APIBase:   "",
        CacheDir:  defaultCacheDir(),
        CacheTTL:  defaultCacheTTL,
        BypassCache: false,
        EnableKEV: true,
    }
}

func defaultCacheDir() string {
    // Prefer $HOME/.bomly/cache/osv; fall back to ./.bomly-cache/osv
    home, err := os.UserHomeDir()
    if err != nil {
        return filepath.Join(".bomly-cache", "osv")
    }
    return filepath.Join(home, ".bomly", "cache", "osv")
}

// Auditor implements scan.Auditor using the OSV API.
type Auditor struct {
    client *Client
    cache  *enrichment.FileCache
    config Config
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

    clientConfig := DefaultClientConfig()
    if config.APIBase != "" {
        clientConfig.APIBase = config.APIBase
    }

    cache, err := enrichment.NewFileCache(config.CacheDir, config.CacheTTL)
    if err != nil {
        return nil, fmt.Errorf("osv auditor: %w", err)
    }

    return &Auditor{
        client: NewClient(clientConfig),
        cache:  cache,
        config: config,
    }, nil
}

// Descriptor returns the auditor registration metadata.
func (a *Auditor) Descriptor() scan.AuditorDescriptor {
    return scan.AuditorDescriptor{
        Name:               "osv-auditor",
        ImplementationType: scan.NativeDetector,
        SupportedEcosystems: []scan.Ecosystem{
            // OSV covers all ecosystems via PURL; list the ones where we have
            // reliable PURL or name+ecosystem data from detectors.
            scan.EcosystemNPM,
            scan.EcosystemGo,
            scan.EcosystemPython,
            scan.EcosystemMaven,
            scan.EcosystemRust,
            scan.EcosystemRuby,
            scan.EcosystemSwift,
            scan.EcosystemDart,
            scan.EcosystemPHP,
            scan.EcosystemDotNet,
        },
        SupportedModes: []scan.TargetMode{
            scan.TargetModeFullGraph,
        },
        Priority: 100,
        Required: false,
    }
}

// Audit resolves vulnerabilities for all packages in the graph.
func (a *Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
    if req.Graph == nil {
        return scan.AuditResult{}, nil
    }

    packages := req.Graph.AllPackages()
    if len(packages) == 0 {
        return scan.AuditResult{Graph: req.Graph, Target: req.Target}, nil
    }

    // Build queries and track which packages map to which query index.
    type indexedPkg struct {
        pkg   *graph.Package
        key   enrichment.CacheKey
        query BatchQuery
    }

    var toFetch []indexedPkg
    var allFindings []scan.Finding

    // First pass: try cache
    for _, pkg := range packages {
        key, query, ok := buildQuery(pkg)
        if !ok {
            continue
        }
        if !a.config.BypassCache {
            var cached []OsvVulnerability
            if found, hit := enrichment.Get[[]OsvVulnerability](a.cache, key); hit {
                cached = found
                for _, v := range cached {
                    allFindings = append(allFindings, MapVulnerability(v, pkg))
                }
                continue
            }
        }
        toFetch = append(toFetch, indexedPkg{pkg: pkg, key: key, query: query})
    }

    // Second pass: batch fetch uncached
    if len(toFetch) > 0 {
        queries := make([]BatchQuery, len(toFetch))
        for i, item := range toFetch {
            queries[i] = item.query
        }
        results, err := a.client.QueryBatch(queries)
        if err != nil {
            // Non-fatal: return what we have with a warning.
            if a.config.Stderr != nil {
                fmt.Fprintf(a.config.Stderr, "warn: osv query failed: %v\n", err)
            }
            return scan.AuditResult{Graph: req.Graph, Target: req.Target, Findings: allFindings}, nil
        }

        for i, result := range results {
            item := toFetch[i]
            // Cache the raw OSV vulns (even empty slices — prevents re-querying for clean packages).
            _ = enrichment.Set(a.cache, item.key, result.Vulns)
            for _, v := range result.Vulns {
                allFindings = append(allFindings, MapVulnerability(v, item.pkg))
            }
        }
    }

    // Optional KEV enrichment pass.
    if a.config.EnableKEV && len(allFindings) > 0 {
        catalog, err := FetchKEVCatalog()
        if err != nil {
            if a.config.Stderr != nil {
                fmt.Fprintf(a.config.Stderr, "warn: kev catalog unavailable: %v\n", err)
            }
        } else {
            allFindings = markKEVFindings(allFindings, catalog)
        }
    }

    return scan.AuditResult{
        Graph:    req.Graph,
        Target:   req.Target,
        Findings: allFindings,
    }, nil
}

// buildQuery constructs a CacheKey and BatchQuery for a package.
// Returns (key, query, true) when the package has enough information to query OSV.
// Returns (_, _, false) when the package should be skipped.
func buildQuery(pkg *graph.Package) (enrichment.CacheKey, BatchQuery, bool) {
    if pkg.Version == "" {
        // OSV requires a version for meaningful results.
        return enrichment.CacheKey{}, BatchQuery{}, false
    }

    // Prefer PURL
    if pkg.PURL != "" {
        key := enrichment.NewCacheKey(pkg.PURL, "", "", "")
        purlPkg := PurlPackage{Purl: pkg.PURL}
        raw, _ := json.Marshal(purlPkg)
        return key, BatchQuery{Package: raw}, true
    }

    // Fall back to name + ecosystem + version
    ecosystem := ecosystemToOSV(pkg.Ecosystem)
    if ecosystem == "" {
        return enrichment.CacheKey{}, BatchQuery{}, false
    }

    key := enrichment.NewCacheKey("", pkg.Name, ecosystem, pkg.Version)
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
// Note: scan.Finding does not have an IsKEV field yet. Adding a reason string
// is the MVP approach. A dedicated field can be added in a follow-up.
func markKEVFindings(findings []scan.Finding, catalog *KEVCatalog) []scan.Finding {
    for i := range findings {
        // Extract aliases from reasons (they are stored as "Also known as: ..." strings).
        // In a follow-up, scan.Finding should carry aliases as a structured field.
        aliases := extractAliasesFromReasons(findings[i].Reasons)
        if catalog.Contains(findings[i].ID, aliases) {
            findings[i].Reasons = append(findings[i].Reasons, "CISA KEV: actively exploited in the wild")
        }
    }
    return findings
}

func extractAliasesFromReasons(reasons []string) []string {
    for _, r := range reasons {
        const prefix = "Also known as: "
        if len(r) > len(prefix) && r[:len(prefix)] == prefix {
            parts := splitCSV(r[len(prefix):])
            return parts
        }
    }
    return nil
}

func splitCSV(s string) []string {
    var result []string
    for _, part := range splitOn(s, ',') {
        trimmed := trimSpace(part)
        if trimmed != "" {
            result = append(result, trimmed)
        }
    }
    return result
}

// splitOn and trimSpace are inline helpers to avoid importing strings in the auditor package.
func splitOn(s string, sep rune) []string {
    var result []string
    start := 0
    for i, r := range s {
        if r == sep {
            result = append(result, s[start:i])
            start = i + 1
        }
    }
    result = append(result, s[start:])
    return result
}

func trimSpace(s string) string {
    for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
        s = s[1:]
    }
    for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
        s = s[:len(s)-1]
    }
    return s
}
```

**Note:** `scan.FindingKindVulnerability` must already exist as a constant in `internal/scan/types.go`. It does.

---

## 6. Changes to `internal/output/output.go`

Extend `PackageRef` to include structured license data. This change applies to **all** scan output, not only `--audit` runs.

```go
// PackageRef identifies a package in command outputs.
type PackageRef struct {
    Name     string   `json:"name"`
    Version  string   `json:"version,omitempty"`
    Scope    string   `json:"scope,omitempty"`
    Purl     string   `json:"purl,omitempty"`
    ID       string   `json:"id,omitempty"`
    Licenses []LicenseRef `json:"licenses"`  // ADD THIS FIELD
}
```

Update `PackageFromGraphPackage` to populate `Licenses`:

```go
func PackageFromGraphPackage(pkg *graph.Package) PackageRef {
    if pkg == nil {
        return PackageRef{}
    }
    ref := PackageRef{
        Name:    pkg.QualifiedName(),
        Version: pkg.Version,
        Scope:   pkg.Scope,
        Purl:    pkg.PURL,
        ID:      pkg.ID,
    }
    if len(pkg.Licenses) > 0 {
        ref.Licenses = make([]string, len(pkg.Licenses))
        for i, l := range pkg.Licenses {
            if l.SPDXExpression != "" {
                ref.Licenses[i] = l.SPDXExpression
            } else {
                ref.Licenses[i] = l.Value
            }
        }
    }
    return ref
}
```

---

## 7. Changes to `internal/cli/scan_cmd.go`

### 7.1 New types added at the top of the file

```go
// auditFinding is the serialised form of one scan.Finding in audit output.
type auditFinding struct {
    ID       string           `json:"id"`
    Kind     string           `json:"kind"`
    Severity string           `json:"severity"`
    Package  output.PackageRef `json:"package"`
    Title    string           `json:"title"`
    Reasons  []string         `json:"reasons,omitempty"`
    Source   string           `json:"source"`
}

// auditSummary aggregates finding counts by severity.
type auditSummary struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
    Unknown  int `json:"unknown"`
    Total    int `json:"total"`
}
```

### 7.2 Extend `scanResponse`

```go
type scanResponse struct {
    SchemaVersion string                   `json:"schema_version"`
    Command       string                   `json:"command"`
    Project       output.ProjectDescriptor `json:"project"`
    Packages      []scanPackagePayload     `json:"packages"`
    // New fields — omitted when --audit is not set:
    Findings      []auditFinding           `json:"findings,omitempty"`
    AuditSummary  *auditSummary            `json:"audit_summary,omitempty"`
    Metadata      output.Metadata          `json:"metadata"`
}
```

### 7.3 New flags

In `newScanCmd`, add alongside the existing flags:

```go
var auditEnabled   bool
var failOnSeverity string

cmd.Flags().BoolVar(&auditEnabled, "audit", false, "Enrich results with vulnerability data from OSV and CISA KEV")
cmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "Exit non-zero if any finding meets or exceeds this severity (critical|high|medium|low)")
```

### 7.4 Audit execution block

After the existing graph resolution and scope filtering, add:

```go
if auditEnabled {
    osvAuditor, err := osv.New(osv.DefaultConfig())
    if err != nil {
        logger.Warn("osv auditor unavailable", zap.Error(err))
    } else {
        ctx.registry.RegisterAuditor(osvAuditor)
    }

    auditResults, auditErr := ctx.engine.Audit(cmd.Context(), scan.AuditRequest{
        ProjectPath:    options.path,
        Ecosystem:      selectedEcosystem,
        PackageManager: selectedPackageManager,
        Mode:           scan.TargetModeFullGraph,
        Graph:          selectedGraph,
        Stderr:         cmd.ErrOrStderr(),
    })
    if auditErr != nil {
        logger.Warn("audit failed", zap.Error(auditErr))
    }

    payload.Findings = mapFindings(auditResults.Findings)
    payload.AuditSummary = buildAuditSummary(auditResults.Findings)

    if failOnSeverity != "" {
        if shouldFail(auditResults.Findings, failOnSeverity) {
            return fmt.Errorf("audit failed: findings at or above %s severity", failOnSeverity)
        }
    }
}
```

### 7.5 Helper functions

```go
func mapFindings(findings []scan.Finding) []auditFinding {
    result := make([]auditFinding, 0, len(findings))
    for _, f := range findings {
        result = append(result, auditFinding{
            ID:       f.ID,
            Kind:     string(f.Kind),
            Severity: f.Severity,
            Package:  output.PackageFromGraphPackage(f.Package),
            Title:    f.Title,
            Reasons:  f.Reasons,
            Source:   f.Source,
        })
    }
    return result
}

func buildAuditSummary(findings []scan.Finding) *auditSummary {
    s := &auditSummary{}
    for _, f := range findings {
        s.Total++
        switch f.Severity {
        case "critical":
            s.Critical++
        case "high":
            s.High++
        case "medium":
            s.Medium++
        case "low":
            s.Low++
        default:
            s.Unknown++
        }
    }
    return s
}

// severityRank maps severity strings to comparable integers.
var severityRank = map[string]int{
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}

func shouldFail(findings []scan.Finding, threshold string) bool {
    thresholdRank, ok := severityRank[threshold]
    if !ok {
        return false
    }
    for _, f := range findings {
        if rank, ok := severityRank[f.Severity]; ok && rank >= thresholdRank {
            return true
        }
    }
    return false
}
```

### 7.6 Text renderer extension

Add an audit section to the existing text renderer in `scan_cmd.go`. After the packages table, if `len(payload.Findings) > 0`:

```
VULNERABILITIES
───────────────────────────────────────────
  CRITICAL  CVE-2024-1234  lodash 4.17.15
            Fix available: upgrade to 4.17.21
            Also known as: GHSA-35jh-r3h4-6jhm
            CISA KEV: actively exploited in the wild

  HIGH      CVE-2023-5678  axios 0.21.1
            Fix available: upgrade to 0.21.2

AUDIT SUMMARY
  Critical: 1  High: 1  Medium: 0  Low: 0
```

---

## 8. Changes to `internal/cli/scan_cmd.go` — import additions

```go
import (
    // existing imports …
    osvauditor "github.com/bomly/bomly-cli/internal/auditors/osv"
)
```

---

## 9. graph.Graph API requirement

The auditor calls `req.Graph.AllPackages()`. Verify this method exists on `*graph.Graph`. If it does not, add it:

```go
// AllPackages returns all packages in the graph in a stable order.
func (g *Graph) AllPackages() []*Package {
    // existing graph traversal
}
```

Check `internal/graph/graph.go` before adding — there may already be a `Packages()` or `Nodes()` method. Use whichever already exists and adapt the auditor accordingly.

---

## 10. Output JSON schema for `scan --audit`

```json
{
  "schema_version": "1.0",
  "command": "scan",
  "project": {
    "name": "my-project",
    "path": ".",
    "ecosystem": "npm",
    "package_manager": "npm"
  },
  "packages": [
    {
      "name": "lodash",
      "version": "4.17.15",
      "scope": "runtime",
      "purl": "pkg:npm/lodash@4.17.15",
      "licenses": ["MIT"],
      "dependencies": []
    }
  ],
  "findings": [
    {
      "id": "CVE-2024-1234",
      "kind": "vulnerability",
      "severity": "critical",
      "package": {
        "name": "lodash",
        "version": "4.17.15",
        "purl": "pkg:npm/lodash@4.17.15",
        "licenses": ["MIT"]
      },
      "title": "Prototype Pollution in lodash",
      "reasons": [
        "Fix available: upgrade to 4.17.21",
        "Also known as: GHSA-35jh-r3h4-6jhm",
        "CISA KEV: actively exploited in the wild"
      ],
      "source": "osv"
    }
  ],
  "audit_summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0,
    "total": 1
  },
  "metadata": {
    "duration_ms": 1420
  }
}
```

---

## 11. Test requirements

### `internal/auditors/osv/auditor_test.go`

The test file must cover:

1. **Packages with PURL** — assert that PURL-based query is built correctly.
2. **Packages without PURL** — assert name+ecosystem+version query is built.
3. **Packages without version** — assert they are skipped (no query built).
4. **Packages with unknown ecosystem** — assert they are skipped.
5. **Cache hit** — populate cache before test; assert no HTTP call is made.
6. **OSV API failure** — use a test HTTP server returning 500; assert non-fatal (returns empty findings, no error).
7. **KEV enrichment** — assert that a finding whose ID is in the KEV catalog gets the KEV reason appended.
8. **Severity extraction** — test `cvssScoreToBand` for each band boundary.

Use `net/http/httptest` for mock HTTP servers. No new test dependencies required.

### `internal/enrichment/cache_test.go`

Cover: TTL expiry (expired entry returns false), round-trip Get/Set, invalid JSON in cached file (returns false gracefully).

---

## 12. AGENTS.md constraint override

Add the following note to `AGENTS.md` under **Non-negotiables**:

```
- OSV and KEV network calls are explicitly permitted behind the --audit flag (see ADR-007).
```

---

## 13. VEX Overlay Support

VEX (Vulnerability Exploitability eXchange) lets teams annotate whether a specific vulnerability actually affects their use of a component. When a VEX document says a component is `not_affected` for a given CVE, that finding should be suppressed — reducing false-positive noise in CI gates.

### 13.1 Supported VEX format

CycloneDX VEX JSON (standalone VEX document or CycloneDX BOM with `vulnerabilities` array). CSAF/CVRF are out of scope for MVP.

Example structure:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "affects": [
        { "ref": "pkg:npm/lodash@4.17.15" }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "This function is never called in our build."
      }
    }
  ]
}
```

VEX states and their effect on findings:

| State | Effect |
|---|---|
| `not_affected` | Finding is suppressed from active list and `--fail-on` evaluation. Added to `suppressed_findings` in output. |
| `false_positive` | Same as `not_affected`. |
| `in_triage` | Finding stays active. Reason `"VEX: under investigation"` is appended. |
| `exploitable` | Finding stays active. Reason `"VEX: confirmed exploitable"` is appended. |
| `affected` | Finding stays active as-is (VEX confirms the OSV finding). |

### 13.2 Files to create

```
internal/enrichment/vex/
  reader.go      — parse CycloneDX VEX JSON; return []VexStatement
  applier.go     — Apply(findings, statements) → (active, suppressed)
```

### 13.3 `internal/enrichment/vex/reader.go`

```go
package vex

import (
    "encoding/json"
    "fmt"
    "os"
)

// VexState is the analysis state from a VEX statement.
type VexState string

const (
    VexStateNotAffected  VexState = "not_affected"
    VexStateFalsePositive VexState = "false_positive"
    VexStateInTriage     VexState = "in_triage"
    VexStateExploitable  VexState = "exploitable"
    VexStateAffected     VexState = "affected"
)

// VexStatement captures one VEX annotation for a (vuln, component) pair.
type VexStatement struct {
    // VulnID is the vulnerability identifier (e.g. "CVE-2024-1234", "GHSA-xxx").
    VulnID string
    // ComponentRefs holds the component identifiers from the VEX affects list.
    // May be PURLs or BOM-ref strings.
    ComponentRefs []string
    // State is the analysis conclusion.
    State VexState
    // Detail is the optional human-readable justification.
    Detail string
}

// wire types for CycloneDX VEX JSON parsing
type cdxVexDoc struct {
    Vulnerabilities []cdxVexVuln `json:"vulnerabilities"`
}

type cdxVexVuln struct {
    ID      string       `json:"id"`
    Affects []cdxAffect  `json:"affects"`
    Analysis cdxAnalysis `json:"analysis"`
}

type cdxAffect struct {
    Ref string `json:"ref"`
}

type cdxAnalysis struct {
    State  string `json:"state"`
    Detail string `json:"detail"`
}

// ReadFile parses a CycloneDX VEX JSON file and returns VEX statements.
func ReadFile(path string) ([]VexStatement, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read vex file %q: %w", path, err)
    }
    return Parse(data)
}

// Parse parses CycloneDX VEX JSON bytes and returns VEX statements.
func Parse(data []byte) ([]VexStatement, error) {
    var doc cdxVexDoc
    if err := json.Unmarshal(data, &doc); err != nil {
        return nil, fmt.Errorf("parse vex document: %w", err)
    }

    statements := make([]VexStatement, 0, len(doc.Vulnerabilities))
    for _, v := range doc.Vulnerabilities {
        if v.ID == "" {
            continue
        }
        refs := make([]string, 0, len(v.Affects))
        for _, a := range v.Affects {
            if a.Ref != "" {
                refs = append(refs, a.Ref)
            }
        }
        statements = append(statements, VexStatement{
            VulnID:        v.ID,
            ComponentRefs: refs,
            State:         VexState(v.Analysis.State),
            Detail:        v.Analysis.Detail,
        })
    }
    return statements, nil
}
```

### 13.4 `internal/enrichment/vex/applier.go`

```go
package vex

import (
    "strings"

    "github.com/bomly/bomly-cli/internal/scan"
)

// Apply partitions findings into active and suppressed based on VEX statements.
// Suppressed findings matched not_affected or false_positive VEX state.
// Active findings may have their VexStatus and Reasons fields annotated.
func Apply(findings []scan.Finding, statements []VexStatement) (active, suppressed []scan.Finding) {
    for i := range findings {
        f := findings[i]
        state, detail := matchStatement(f, statements)
        switch state {
        case VexStateNotAffected, VexStateFalsePositive:
            f.VexStatus = string(state)
            suppressed = append(suppressed, f)
        case VexStateInTriage:
            f.VexStatus = string(state)
            f.Reasons = append(f.Reasons, "VEX: under investigation")
            if detail != "" {
                f.Reasons = append(f.Reasons, "VEX detail: "+detail)
            }
            active = append(active, f)
        case VexStateExploitable:
            f.VexStatus = string(state)
            f.Reasons = append(f.Reasons, "VEX: confirmed exploitable")
            active = append(active, f)
        default:
            // No matching VEX statement or state "affected" — keep as-is.
            active = append(active, f)
        }
    }
    return active, suppressed
}

// matchStatement finds the first VEX statement that applies to this finding.
// Returns ("", "") if no statement matches.
func matchStatement(f scan.Finding, statements []VexStatement) (VexState, string) {
    for _, s := range statements {
        if !vulnIDMatches(f.ID, s.VulnID) {
            continue
        }
        if componentMatches(f, s.ComponentRefs) {
            return s.State, s.Detail
        }
    }
    return "", ""
}

func vulnIDMatches(findingID, stmtID string) bool {
    return strings.EqualFold(findingID, stmtID)
}

// componentMatches checks if any component ref in the VEX statement matches
// the finding's package by PURL or by name@version.
func componentMatches(f scan.Finding, refs []string) bool {
    if f.Package == nil {
        // No package context — apply the statement to all findings for this vuln.
        return true
    }
    if len(refs) == 0 {
        // VEX statement applies to all components for this vuln.
        return true
    }
    for _, ref := range refs {
        if f.Package.PURL != "" && strings.EqualFold(f.Package.PURL, ref) {
            return true
        }
        nameVersion := f.Package.Name + "@" + f.Package.Version
        if strings.EqualFold(nameVersion, ref) {
            return true
        }
    }
    return false
}
```

### 13.5 Changes to `scan.Finding`

In `internal/scan/types.go`, add `VexStatus string` to `Finding`:

```go
// Finding describes a normalized audit result.
type Finding struct {
    ID        string
    Kind      FindingKind
    Package   *graph.Package
    Title     string
    Severity  string
    Reasons   []string
    Source    string
    VexStatus string  // ADD: "not_affected", "in_triage", "exploitable", or empty
}
```

### 13.6 Changes to `scan_cmd.go`

Add `--vex <path>` flag (repeatable) and integrate VEX applier after OSV results:

```go
var vexPaths []string
cmd.Flags().StringArrayVar(&vexPaths, "vex", nil, "Path to a CycloneDX VEX JSON file (repeatable)")
```

After the OSV audit block and before the `--fail-on` check:

```go
if len(vexPaths) > 0 {
    var allStatements []vex.VexStatement
    for _, p := range vexPaths {
        stmts, err := vex.ReadFile(p)
        if err != nil {
            if a.config.Stderr != nil {
                fmt.Fprintf(cmd.ErrOrStderr(), "warn: vex file %q: %v\n", p, err)
            }
            continue
        }
        allStatements = append(allStatements, stmts...)
    }
    activeFindings, suppressedFindings := vex.Apply(auditResults.Findings, allStatements)
    auditResults.Findings = activeFindings
    payload.SuppressedFindings = mapFindings(suppressedFindings) // new field in scanResponse
}
```

Add `SuppressedFindings []auditFinding \`json:"suppressed_findings,omitempty"\`` to `scanResponse`.

---

## 14. License Enrichment — Surfacing and Undeclared-License Findings

### 14.1 How licenses get into the graph

Detectors (native and Syft-backed) already populate `graph.Package.Licenses []PackageLicense`, where each `PackageLicense` has:
- `Value` — raw license string from the manifest (e.g., "MIT", "Apache-2.0")
- `SPDXExpression` — normalized SPDX expression when available
- `Type` — how the license was determined

No external API call is needed. License data is already in the graph at scan time.

### 14.2 Surfacing in scan output (all modes)

`output.PackageRef.Licenses []LicenseRef` is populated by `PackageFromGraphPackage()`. This change is already described in section 6 and applies to **all scan output**, not only `--audit` runs.

The `SPDXExpression` is preferred over `Value`. If neither is set, the entry is omitted from the `Licenses` slice.

### 14.3 Undeclared-license findings (audit mode only)

When `--audit` is set, packages with no declared license generate a finding:

```go
if len(pkg.Licenses) == 0 {
    findings = append(findings, scan.Finding{
        ID:       "BOMLY-NO-LICENSE-" + pkg.ID,
        Kind:     scan.FindingKindPolicy,
        Package:  pkg,
        Title:    "No license declared",
        Severity: "medium",
        Reasons:  []string{"Package declares no license expression. License obligations are unknown."},
        Source:   "bomly",
    })
}
```

This is emitted by the OSV auditor's `Audit()` method alongside vulnerability findings. It uses `FindingKindPolicy` (already defined in `scan.FindingKind`).

### 14.4 What is NOT in scope for the CLI

- License allow/deny/review policy evaluation: requires a configuration file (allow list, deny list, review list) and organizational context. This is a **portal feature**.
- Copyleft propagation analysis: requires graph BFS to detect copyleft-under-proprietary conflicts. This is a **portal feature**.
- External license lookup (ClearlyDefined, Libraries.io): some packages may omit license metadata from their manifests but declare it in registry metadata. Fetching it is a future enrichment pass, not in current scope.

---

## 15. SBOM Diff via Syft

### 15.1 Purpose

`bomly diff` currently compares two git refs. The new mode compares two pre-existing SBOM files (CycloneDX or SPDX JSON). This is useful when:
- You have SBOMs generated by another tool and want to compare them
- You want to compare container image SBOMs without re-running Syft from scratch
- You are diffing SBOM outputs from a CI pipeline against a baseline

### 15.2 Syft as the SBOM source

The Syft detector already declares `sbom-import` in its `Capabilities` and supports `EcosystemSBOM` / `PackageManagerSBOM`. Syft's Go library can read a CycloneDX or SPDX file as a source — this is how the detector handles `PackageManagerSBOM` targets. No new code is required in the Syft detector itself.

### 15.3 New flags on `diff`

```go
var baseSBOMPath string
var headSBOMPath string

cmd.Flags().StringVar(&baseSBOMPath, "base-sbom", "", "Path to the base SBOM file (CycloneDX or SPDX JSON)")
cmd.Flags().StringVar(&headSBOMPath, "head-sbom", "", "Path to the head SBOM file (CycloneDX or SPDX JSON)")
```

Validation rules:
- `--base-sbom` and `--head-sbom` must both be provided together or not at all
- If `--base-sbom` / `--head-sbom` are set, `--base` and `--head` must not be set
- `--url` and `--container` are incompatible with `--base-sbom` / `--head-sbom`

### 15.4 `resolveSBOMDiffGraphs()` in `diff_cmd.go`

```go
func resolveSBOMDiffGraphs(
    options *globalOptions,
    logger *zap.Logger,
    basePath, headPath string,
    stderr io.Writer,
) ([]scan.ResolveGraphResult, []scan.ResolveGraphResult, string, error) {

    baseResults, err := resolveFromSBOMFile(options, logger, basePath, stderr)
    if err != nil {
        return nil, nil, "", fmt.Errorf("resolve base SBOM %q: %w", basePath, err)
    }

    headResults, err := resolveFromSBOMFile(options, logger, headPath, stderr)
    if err != nil {
        return nil, nil, "", fmt.Errorf("resolve head SBOM %q: %w", headPath, err)
    }

    label := fmt.Sprintf("%s vs %s", filepath.Base(basePath), filepath.Base(headPath))
    return baseResults, headResults, label, nil
}

func resolveFromSBOMFile(
    options *globalOptions,
    logger *zap.Logger,
    sbomPath string,
    stderr io.Writer,
) ([]scan.ResolveGraphResult, error) {

    absPath, err := filepath.Abs(sbomPath)
    if err != nil {
        return nil, fmt.Errorf("resolve path: %w", err)
    }

    req := scan.ResolveGraphRequest{
        ProjectPath: absPath,
        ExecutionTarget: scan.ExecutionTarget{
            Kind: scan.ExecutionTargetFileSystem,
            Path: absPath,
        },
        Subproject: scan.Subproject{
            Path:           absPath,
            RelativePath:   filepath.Base(absPath),
            PackageManager: scan.PackageManagerSBOM,
            Ecosystem:      scan.EcosystemSBOM,
        },
        Ecosystem:      scan.EcosystemSBOM,
        PackageManager: scan.PackageManagerSBOM,
        Mode:           scan.TargetModeFullGraph,
        Stderr:         stderr,
    }

    // Build a registry with the Syft detector and run via engine.
    registry := scan.NewRegistry()
    // Syft detector is registered in the resolveGraphs helper; here we
    // call the engine directly with a pre-built request.
    engine := scan.NewEngine(registry)
    result, err := engine.ResolveGraph(context.Background(), req)
    if err != nil {
        return nil, err
    }
    return []scan.ResolveGraphResult{result}, nil
}
```

**Note:** The agent implementing this should verify the exact call path for Syft detector registration (see `internal/cli/resolver.go` and the existing `resolveGraphs` helper). The Syft detector must be registered in the registry that the engine uses. Mirror whatever registration pattern `scan_cmd.go` uses for the full-graph case.

### 15.5 Diff output changes

When `--base-sbom` / `--head-sbom` are used:
- The `comparison.base` and `comparison.head` fields in the JSON output show the file paths (not git refs)
- The `project.path` shows the working directory

No changes to the diff engine or rendering logic.

---

## 16. SARIF Output

### 16.1 What SARIF is and why include it

SARIF (Static Analysis Results Interchange Format, OASIS standard, version 2.1.0) is the exchange format security tools use to integrate with developer platforms. GitHub's `upload-sarif` action ingests SARIF files and surfaces findings as:
- Inline PR annotations identifying the package with the vulnerability
- Entries in the repository's Security tab (Code scanning alerts)
- Dismissal and suppression workflows built into GitHub

Including SARIF output in bomly-cli means a single `bomly scan --audit --format sarif > results.sarif` command makes vulnerability findings first-class citizens in GitHub PRs. The implementation cost is a single file (~180 LOC) with no new dependencies. The return on that investment — automatic GitHub PR integration for any project using bomly — is disproportionate.

**Decision: include SARIF in scope.**

### 16.2  `internal/output/sarif.go`

```go
package output

import (
    "encoding/json"
    "fmt"
    "io"

    "github.com/bomly/bomly-cli/internal/scan"
)

const (
    sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    sarifVersion = "2.1.0"
    osvHelpBase  = "https://osv.dev/vulnerability/"
)

// sarifLog is the root SARIF 2.1.0 document.
type sarifLog struct {
    Schema  string     `json:"$schema"`
    Version string     `json:"version"`
    Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
    Tool    sarifTool     `json:"tool"`
    Results []sarifResult `json:"results"`
}

type sarifTool struct {
    Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
    Name           string      `json:"name"`
    Version        string      `json:"version"`
    InformationURI string      `json:"informationUri"`
    Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
    ID               string          `json:"id"`
    ShortDescription sarifMessage    `json:"shortDescription"`
    FullDescription  sarifMessage    `json:"fullDescription"`
    DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
    HelpURI          string          `json:"helpUri,omitempty"`
}

type sarifRuleConfig struct {
    Level string `json:"level"`
}

type sarifResult struct {
    RuleID    string          `json:"ruleId"`
    Level     string          `json:"level"`
    Message   sarifMessage    `json:"message"`
    Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
    PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
    ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
    URI       string `json:"uri"`
    URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifMessage struct {
    Text string `json:"text"`
}

// WriteSARIF writes findings as a SARIF 2.1.0 document to w.
// toolName and toolVersion are used to populate the driver section.
func WriteSARIF(w io.Writer, findings []scan.Finding, toolName, toolVersion string) error {
    // Deduplicate rules by finding ID.
    seen := map[string]bool{}
    var rules []sarifRule
    for _, f := range findings {
        if seen[f.ID] {
            continue
        }
        seen[f.ID] = true
        helpURI := ""
        if f.Source == "osv" {
            helpURI = osvHelpBase + f.ID
        }
        rules = append(rules, sarifRule{
            ID:               f.ID,
            ShortDescription: sarifMessage{Text: f.Title},
            FullDescription:  sarifMessage{Text: joinReasons(f.Reasons)},
            DefaultConfig:    sarifRuleConfig{Level: severityToSARIFLevel(f.Severity)},
            HelpURI:          helpURI,
        })
    }

    results := make([]sarifResult, 0, len(findings))
    for _, f := range findings {
        pkgName := ""
        pkgVersion := ""
        if f.Package != nil {
            pkgName = f.Package.QualifiedName()
            pkgVersion = f.Package.Version
        }
        msgText := f.Title
        if pkgName != "" {
            msgText = fmt.Sprintf("%s in %s@%s", f.Title, pkgName, pkgVersion)
        }
        artifactURI := pkgName
        if artifactURI == "" {
            artifactURI = f.ID
        }
        results = append(results, sarifResult{
            RuleID:  f.ID,
            Level:   severityToSARIFLevel(f.Severity),
            Message: sarifMessage{Text: msgText},
            Locations: []sarifLocation{
                {
                    PhysicalLocation: sarifPhysicalLocation{
                        ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
                    },
                },
            },
        })
    }

    log := sarifLog{
        Schema:  sarifSchema,
        Version: sarifVersion,
        Runs: []sarifRun{
            {
                Tool: sarifTool{
                    Driver: sarifDriver{
                        Name:           toolName,
                        Version:        toolVersion,
                        InformationURI: "https://bomly.dev",
                        Rules:          rules,
                    },
                },
                Results: results,
            },
        },
    }

    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    return enc.Encode(log)
}

func severityToSARIFLevel(severity string) string {
    switch severity {
    case "critical", "high":
        return "error"
    case "medium":
        return "warning"
    default:
        return "note"
    }
}

func joinReasons(reasons []string) string {
    result := ""
    for i, r := range reasons {
        if i > 0 {
            result += " "
        }
        result += r
    }
    return result
}
```

### 16.3 Triggering SARIF from `scan_cmd.go`

Add `"sarif"` as a valid `--format` value. When `format == "sarif"`, call `WriteSARIF` instead of `output.Write`:

```go
if graphOutputFormat == output.FormatSARIF {
    // SARIF output: requires --audit to have findings.
    if !auditEnabled {
        return invalidInputf("--format sarif requires --audit")
    }
    return output.WriteSARIF(cmd.OutOrStdout(), auditResults.Findings, "bomly", options.CoreVersion)
}
```

Add `FormatSARIF Format = "sarif"` to `output/output.go` alongside `FormatJSON` and `FormatText`. Update `ParseFormat` to accept `"sarif"`.

### 16.4 GitHub Actions usage example

```yaml
- name: Scan dependencies
  run: bomly scan --audit --format sarif > bomly-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bomly-results.sarif
    category: bomly
```

---

## 17. Grype Auditor and `--auditors` / `--exclude-auditors` Flags

### 17.1 Motivation

Grype (by Anchore) provides an independent vulnerability database (GHSA, NVD, RHEL, Ubuntu, Alpine, Wolfi, and more) that complements OSV by covering OS-level packages and additional language ecosystems. Running both OSV and Grype yields broader coverage and cross-validation; findings from both sources are deduplicated by the engine using `Finding.ID`.

Agents implementing Grype MUST follow the same `ThirdPartyDetector` subprocess pattern used by all third-party integrations. Grype is invoked as an external binary — it is NOT linked as a Go library.

### 17.2 `AuditorFilter` — new type in `internal/scan/types.go`

Add `AuditorFilter` immediately after `DetectorFilter` in `types.go`. Mirror `DetectorFilter` exactly:

```go
// AuditorFilter narrows auditor selection for a request.
type AuditorFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether an auditor name is explicitly allowed.
func (f AuditorFilter) Includes(name string) bool {
	if len(f.Include) == 0 {
		return true
	}
	for _, candidate := range f.Include {
		if candidate == name {
			return true
		}
	}
	return false
}

// Excludes reports whether an auditor name is explicitly denied.
func (f AuditorFilter) Excludes(name string) bool {
	for _, candidate := range f.Exclude {
		if candidate == name {
			return true
		}
	}
	return false
}
```

Add `AuditorFilter AuditorFilter` as a field on `AuditRequest`:

```go
// AuditRequest defines input for an auditor.
type AuditRequest struct {
    ProjectPath     string
    ExecutionTarget ExecutionTarget
    SubprojectInfo  Subproject
    Ecosystem       Ecosystem
    PackageManager  PackageManager
    Mode            TargetMode
    Query           ComponentQuery
    Graph           *graph.Graph
    Target          *graph.Package
    AuditorFilter   AuditorFilter   // ← new field
    Stderr          io.Writer
}
```

### 17.3 `AuditorDescriptors()` and name filtering in `internal/scan/registry.go`

Add `AuditorDescriptors()` to `Registry` (mirrors `DetectorDescriptors()`):

```go
// AuditorDescriptors returns descriptors for all registered auditors.
func (r *Registry) AuditorDescriptors() []AuditorDescriptor {
    out := make([]AuditorDescriptor, len(r.auditors))
    for i, a := range r.auditors {
        out[i] = a.Descriptor()
    }
    return out
}
```

Update `Auditors(req AuditRequest)` to skip auditors whose name is excluded or not included:

```go
func (r *Registry) Auditors(req AuditRequest) []Auditor {
    var matched []Auditor
    for _, a := range r.auditors {
        d := a.Descriptor()

        // Apply name-based include/exclude filter (mirrors Detectors behaviour).
        if !req.AuditorFilter.Includes(d.Name) || req.AuditorFilter.Excludes(d.Name) {
            continue
        }

        // Ecosystem filter.
        if len(d.SupportedEcosystems) > 0 {
            found := false
            for _, e := range d.SupportedEcosystems {
                if e == req.Ecosystem {
                    found = true
                    break
                }
            }
            if !found {
                continue
            }
        }

        // Mode filter.
        if len(d.SupportedModes) > 0 {
            found := false
            for _, m := range d.SupportedModes {
                if m == req.Mode {
                    found = true
                    break
                }
            }
            if !found {
                continue
            }
        }

        matched = append(matched, a)
    }
    // Sort by descending priority (highest priority runs first).
    sort.Slice(matched, func(i, j int) bool {
        return matched[i].Descriptor().Priority > matched[j].Descriptor().Priority
    })
    return matched
}
```

> **Note:** Check whether the existing `Auditors()` implementation already sorts by priority. If it does, do not add a second sort.

### 17.4 Flags in `internal/cli/options.go`

Add two fields to `globalOptions`:

```go
Auditors        string // value of --auditors
ExcludeAuditors string // value of --exclude-auditors
```

Bind persistent root flags immediately after `--detectors` / `--exclude-detectors`:

```go
rootCmd.PersistentFlags().StringVar(&options.Auditors, "auditors", "",
    "comma-separated list of auditors to use (default: all registered auditors)")
rootCmd.PersistentFlags().StringVar(&options.ExcludeAuditors, "exclude-auditors", "",
    "comma-separated list of auditors to exclude")
```

### 17.5 Shell completions in `internal/cli/flag_options.go`

Add `availableAuditorOptions()` (mirrors `availableDetectorOptions()`):

```go
func availableAuditorOptions(logger *zap.Logger) []string {
    registry := buildScanRegistry(logger)
    descriptors := registry.AuditorDescriptors()
    names := make([]string, len(descriptors))
    for i, d := range descriptors {
        names[i] = d.Name
    }
    return names
}
```

Register completions in `bindDynamicFlagOptions()` immediately after the `--detectors` / `--exclude-detectors` block:

```go
_ = rootCmd.RegisterFlagCompletionFunc("auditors", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
    return availableAuditorOptions(logger), cobra.ShellCompDirectiveNoFileComp
})
_ = rootCmd.RegisterFlagCompletionFunc("exclude-auditors", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
    return availableAuditorOptions(logger), cobra.ShellCompDirectiveNoFileComp
})
```

### 17.6 Parsing flags into `AuditorFilter` in `scan_cmd.go`

When building the `AuditRequest` inside the `--audit` block, parse `options.Auditors` and `options.ExcludeAuditors` exactly as `options.Detectors` and `options.ExcludeDetectors` are parsed into `DetectorFilter`:

```go
auditorFilter := scan.AuditorFilter{
    Include: splitCommaSeparated(options.Auditors),
    Exclude: splitCommaSeparated(options.ExcludeAuditors),
}
// Pass auditorFilter into AuditRequest.AuditorFilter.
```

> `splitCommaSeparated` is the helper that already exists for detector filter parsing — reuse it.

### 17.7 Package: `internal/auditors/grype/auditor.go`

Grype is invoked as an external subprocess. The auditor calls `grype <sbom-or-purl> -o json` and parses the output.

```go
package grype

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "os/exec"

    "github.com/bomly/bomly-cli/internal/scan"
)

const auditorName = "grype"

// Auditor invokes the Grype binary and translates its JSON output into scan.Findings.
type Auditor struct {
    Priority int
}

// Descriptor describes the Grype auditor.
func (a Auditor) Descriptor() scan.AuditorDescriptor {
    return scan.AuditorDescriptor{
        Name:               auditorName,
        ImplementationType: scan.ThirdPartyDetector,
        // Empty SupportedEcosystems means all ecosystems — Grype handles them all.
        SupportedEcosystems: nil,
        SupportedModes:      []scan.TargetMode{scan.TargetModeFullGraph},
        Priority:            a.Priority,
        Required:            false,
    }
}

// Ready reports whether the grype binary is available on PATH.
func (a Auditor) Ready() bool {
    _, err := exec.LookPath("grype")
    return err == nil
}

// Audit runs grype against each package in the graph using its PURL.
// Packages without a PURL are skipped.
func (a Auditor) Audit(ctx context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
    if req.Graph == nil {
        return scan.AuditResult{Graph: req.Graph, Target: req.Target}, nil
    }

    if !a.Ready() {
        return scan.AuditResult{Graph: req.Graph, Target: req.Target},
            fmt.Errorf("grype is not installed or not on PATH; install from https://github.com/anchore/grype")
    }

    var findings []scan.Finding
    for _, pkg := range req.Graph.Packages {
        if pkg.PURL == "" {
            continue
        }
        pkgFindings, err := runGrype(ctx, pkg.PURL, &pkg)
        if err != nil {
            // Log and continue — partial results are better than no results.
            _, _ = fmt.Fprintf(req.Stderr, "grype: warning: %v\n", err)
            continue
        }
        findings = append(findings, pkgFindings...)
    }

    return scan.AuditResult{
        Graph:    req.Graph,
        Target:   req.Target,
        Findings: findings,
    }, nil
}

// --- internal helpers ---

// grypematch is the subset of Grype's JSON that bomly needs.
type grypeMatch struct {
    Vulnerability struct {
        ID          string   `json:"id"`
        Severity    string   `json:"severity"`
        Description string   `json:"description"`
        Namespace   string   `json:"namespace"`
        Fix         struct {
            State string `json:"state"`
        } `json:"fix"`
        URLs []string `json:"urls"`
    } `json:"vulnerability"`
    Artifact struct {
        Name    string `json:"name"`
        Version string `json:"version"`
        PURL    string `json:"purl"`
    } `json:"artifact"`
}

type grypeOutput struct {
    Matches []grypeMatch `json:"matches"`
}

// runGrype executes `grype <purl> -o json` and parses the output.
func runGrype(ctx context.Context, purl string, pkg *scan.Package) ([]scan.Finding, error) {
    // #nosec G204 — purl is derived from the resolved dependency graph, not user-controlled CLI input.
    cmd := exec.CommandContext(ctx, "grype", purl, "-o", "json", "-q")
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("grype failed for %s: %w (stderr: %s)", purl, err, stderr.String())
    }

    var out grypeOutput
    if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
        return nil, fmt.Errorf("grype: failed to parse output for %s: %w", purl, err)
    }

    findings := make([]scan.Finding, 0, len(out.Matches))
    for _, m := range out.Matches {
        findings = append(findings, scan.Finding{
            ID:       m.Vulnerability.ID,
            Kind:     scan.FindingKindVulnerability,
            Package:  pkg,
            Title:    m.Vulnerability.Description,
            Severity: normalizeSeverity(m.Vulnerability.Severity),
            Source:   auditorName + "/" + m.Vulnerability.Namespace,
        })
    }
    return findings, nil
}

func normalizeSeverity(grypeLevel string) string {
    switch grypeLevel {
    case "Critical":
        return "critical"
    case "High":
        return "high"
    case "Medium":
        return "medium"
    case "Low":
        return "low"
    default:
        return "unknown"
    }
}
```

> **Note on `pkg` type**: The `pkg` parameter above uses `*scan.Package` for illustration. In the actual codebase, the package type is `*graph.Package` from `github.com/bomly/bomly-cli/internal/graph`. Adjust imports accordingly — use `graph.Package` wherever `scan.Package` appears in the sketch above.

### 17.8 Registration in `internal/cli/resolver.go`

Register both auditors in `buildScanRegistry`. Remove the noop auditors — they are only needed as placeholders before real auditors exist. Once OSV and Grype are registered they replace noop:

```go
// Replace the noop loop with:
registry.RegisterAuditor(osv.Auditor{Priority: 100})
registry.RegisterAuditor(grype.Auditor{Priority:  90})
```

OSV runs first (priority 100). Grype runs second (priority 90). The engine deduplicates findings by `Finding.ID` after aggregating from all auditors.

### 17.9 Tests for `internal/auditors/grype/auditor_test.go`

Minimum test coverage:

| Test | Scenario |
|---|---|
| `TestDescriptor` | Name is `"grype"`, implementation type is `ThirdPartyDetector`, required is `false` |
| `TestReadyFalse` | Temporarily shadow PATH so `grype` cannot be found; `Ready()` returns `false` |
| `TestAuditNilGraph` | `Audit` with `req.Graph == nil` returns empty result without error |
| `TestAuditSkipsNoPURL` | Package with empty PURL is skipped; no subprocess is launched |
| `TestNormalizeSeverity` | All Grype severity levels map to lowercase equivalents; unknown maps to `"unknown"` |
| `TestParseGrypeOutput` | Golden-file JSON of Grype output (HTTP fixture) → expected `[]scan.Finding` |

Do NOT use `exec.Command` directly in tests. Extract `runGrype` as a package-level variable of function type so tests can inject a stub:

```go
// In auditor.go — replace the direct call with an indirection:
var execGrype = runGrype  // package-level var; overridable in tests

// In Audit():
pkgFindings, err := execGrype(ctx, pkg.PURL, &pkg)
```

### 17.10 Flag usage examples

```
# Use all registered auditors (default — both OSV and Grype):
bomly scan --audit

# Use only OSV:
bomly scan --audit --auditors osv

# Use only Grype:
bomly scan --audit --auditors grype

# Use all auditors except Grype:
bomly scan --audit --exclude-auditors grype
```

---

## 18. Portal Features — Explicitly Out of Scope for the CLI

The following features are reserved for Bomly's paid SBOM management portal. They are **not to be implemented in bomly-cli**.

| Feature | Why it belongs in the portal |
|---|---|
| License policy evaluation (allow/deny/review lists) | Requires team-level config, organizational context, and policy management UX |
| Copyleft propagation analysis | Requires persistent graph storage and historical dependency graph data |
| SBOM quality scoring (NTIA, CRA, FDA, NIST) | Requires baseline tracking, trend analysis, and compliance reporting workflows |
| Compliance gap reporting | Requires regulation-specific templates and audit trail |

The CLI is responsible for generating accurate, enriched output. The portal consumes that output and applies policy decisions. Agents implementing CLI features must not add any of the above to the CLI scope.

---

## 19. Execution order for agents

Implement in this order to avoid compilation errors:

1. `internal/scan/types.go` — add `VexStatus string` to `Finding`; add `AuditorFilter` type with `Includes`/`Excludes` methods; add `AuditorFilter AuditorFilter` field to `AuditRequest`
2. `internal/scan/registry.go` — add `AuditorDescriptors()` method; apply `AuditorFilter` name-based filtering in `Auditors()`
3. `internal/cli/options.go` — add `Auditors string` and `ExcludeAuditors string` fields; bind `--auditors` / `--exclude-auditors` persistent root flags
4. `internal/cli/flag_options.go` — add `availableAuditorOptions()`; register `--auditors` / `--exclude-auditors` completions in `bindDynamicFlagOptions()`
5. `internal/enrichment/cache.go`
6. `internal/enrichment/vex/reader.go`
7. `internal/enrichment/vex/applier.go`
8. `internal/auditors/osv/response.go`
9. `internal/auditors/osv/client.go`
10. `internal/auditors/osv/mapper.go`
11. `internal/auditors/osv/kev.go`
12. `internal/auditors/osv/auditor.go` (include undeclared-license findings)
13. `internal/auditors/grype/auditor.go`
14. `internal/cli/resolver.go` — replace noop auditor loop with OSV + Grype registrations
15. `internal/output/output.go` — extend `PackageRef` + `PackageFromGraphPackage`; add `FormatSARIF`
16. `internal/output/sarif.go`
17. `internal/cli/scan_cmd.go` — add `--audit`, `--vex`, `--fail-on`, `--format sarif` flags; audit block; `AuditorFilter` parsing; VEX applier; SARIF dispatch
18. `internal/cli/diff_cmd.go` — add `--base-sbom` / `--head-sbom`; `resolveSBOMDiffGraphs()`; `resolveFromSBOMFile()`
19. `internal/auditors/osv/auditor_test.go`
20. `internal/auditors/grype/auditor_test.go`
21. `internal/enrichment/cache_test.go`
22. `internal/enrichment/vex/reader_test.go`
23. `internal/enrichment/vex/applier_test.go`
24. `internal/output/sarif_test.go`
25. `docs/ADRs/README.md` — register ADR-007
26. `AGENTS.md` — constraint override note

After step 14, run `make build` and `make test` to verify compilation and existing tests pass before writing new tests.

---

## 20. Out of scope (remaining future work)

| Feature | Suggested location |
|---|---|
| Standalone `audit` command | `internal/cli/audit_cmd.go` + ADR-008 |
| EOL detection | `internal/enrichment/eol/` |
| KEV catalog caching (separate TTL) | `internal/enrichment/cache.go` extension |
| `--no-cache` / `--refresh` flag | `internal/cli/scan_cmd.go` |
| Reachability analysis | `internal/graph/reachability.go` |
| External license lookup (ClearlyDefined) | `internal/enrichment/licenses/` |
| CSAF/CVRF VEX format | `internal/enrichment/vex/` extension |
| License policy engine | **Portal only** |
| SBOM quality scoring | **Portal only** |
