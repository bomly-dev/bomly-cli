package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// ProxyURL is an optional HTTP proxy URL for external network requests.
	ProxyURL string
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
	http   *http.Client
	config ClientConfig
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
	transport := http.DefaultTransport
	if config.ProxyURL != "" {
		if proxyURL, err := url.Parse(config.ProxyURL); err == nil {
			transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	return &Client{
		http:   &http.Client{Timeout: config.Timeout, Transport: transport},
		config: config,
	}
}

// GetVuln fetches the full vulnerability record for the given OSV ID.
// Use this after querybatch to enrich the minimal VulnRef data.
func (c *Client) GetVuln(id string) (*OsvVulnerability, error) {
	endpoint := c.config.APIBase + "/v1/vulns/" + url.PathEscape(id) // #nosec G107 — base URL from config

	resp, err := c.http.Get(endpoint) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("osv get vuln %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("osv: vuln %s not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv get vuln %s: status %d", id, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB per vuln
	if err != nil {
		return nil, fmt.Errorf("osv read vuln %s: %w", id, err)
	}
	var vuln OsvVulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("osv unmarshal vuln %s: %w", id, err)
	}
	return &vuln, nil
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
