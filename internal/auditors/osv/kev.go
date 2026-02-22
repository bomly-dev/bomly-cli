package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	audcache "github.com/bomly/bomly-cli/internal/auditors/cache"
)

const (
	kevURL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevFetchTimeout = 15 * time.Second
	kevCacheKey     = "kev-catalog"
	// defaultKEVCacheTTL is intentionally longer than the OSV TTL; the KEV catalog
	// is updated less frequently than individual vulnerability queries.
	defaultKEVCacheTTL = 6 * time.Hour
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

// FetchKEVCatalog downloads the CISA KEV catalog, using the provided cache when available.
// cache may be nil — in that case the catalog is always fetched fresh.
// proxyURL is an optional HTTP proxy (empty string = no proxy).
// Returns (nil, nil) if the request fails — callers treat absence as informational.
func FetchKEVCatalog(cache *audcache.FileCache, proxyURL string) (*KEVCatalog, error) {
	cacheKeyObj := audcache.NewKey(kevCacheKey, "", "", "")

	if cache != nil {
		if found, hit := audcache.Get[*KEVCatalog](cache, cacheKeyObj); hit && found != nil {
			return found, nil
		}
	}

	transport := http.DefaultTransport
	if proxyURL != "" {
		if parsed, err := url.Parse(proxyURL); err == nil {
			transport = &http.Transport{Proxy: http.ProxyURL(parsed)}
		}
	}
	client := &http.Client{Timeout: kevFetchTimeout, Transport: transport}
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

	if cache != nil {
		_ = audcache.Set(cache, cacheKeyObj, catalog)
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
