package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const (
	defaultAPIBase   = "https://api.osv.dev"
	defaultTimeout   = 30 * time.Second
	defaultBatchSize = 1000
	maxRetries       = 3
)

// ClientConfig configures the OSV HTTP client.
type ClientConfig struct {
	APIBase            string
	Timeout            time.Duration
	BatchSize          int
	HTTPClient         *http.Client
	HTTPClientProvider *sdk.HTTPClientProvider
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
	httpClient := config.HTTPClient
	if httpClient == nil {
		provider := config.HTTPClientProvider
		if provider == nil {
			provider, _ = sdk.NewHTTPClientProviderFromEnv()
			if provider == nil {
				provider, _ = sdk.NewHTTPClientProvider(sdk.HTTPClientConfig{})
			}
		}
		httpClient = provider.Client(config.Timeout)
	}
	return &Client{
		http:   httpClient,
		config: config,
	}
}

// GetVuln fetches the full vulnerability record for the given OSV ID.
// Use this after query batch to enrich the minimal VulnRef data.
func (c *Client) GetVuln(id string) (*Vulnerability, error) {
	endpoint := c.config.APIBase + "/v1/vulns/" + url.PathEscape(id) // #nosec G107 — base URL from config

	resp, err := c.http.Get(endpoint) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("osv get vuln %s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	var vuln Vulnerability
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

	endpoint := c.config.APIBase + "/v1/querybatch"

	var last error
	for attempt := 0; attempt < maxRetries; attempt++ {
		results, retryErr, fatalErr := c.queryChunkAttempt(endpoint, body, attempt)
		if fatalErr != nil {
			return nil, fatalErr
		}
		if retryErr != nil {
			last = retryErr
			continue
		}
		return results, nil
	}
	return nil, last
}

// queryChunkAttempt performs a single OSV batch request. It returns the parsed
// results on success, a non-nil retryErr when the caller should retry, or a
// non-nil fatalErr when the response is unrecoverable. The response body is
// always closed before returning so retries do not leak connections.
func (c *Client) queryChunkAttempt(endpoint string, body []byte, attempt int) (results []BatchResult, retryErr, fatalErr error) {
	resp, err := c.http.Post(endpoint, "application/json", bytes.NewReader(body)) // #nosec G107 — URL is from config, not user input
	if err != nil {
		return nil, fmt.Errorf("osv request attempt %d: %w", attempt+1, err), nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned status %d", resp.StatusCode), nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB limit
	if err != nil {
		return nil, fmt.Errorf("osv read response: %w", err), nil
	}

	var batch BatchResponse
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, nil, fmt.Errorf("osv unmarshal response: %w", err)
	}
	return batch.Results, nil, nil
}
