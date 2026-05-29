package scorecard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const (
	defaultAPIBase = "https://api.scorecard.dev"
	defaultTimeout = 15 * time.Second
)

// ErrProjectNotScored is returned by FetchProject when api.scorecard.dev has
// no run for the requested repository (HTTP 404). Callers should treat this
// as a benign skip, not a failure.
var ErrProjectNotScored = errors.New("scorecard: project not scored")

// ClientConfig configures the Scorecard HTTP client.
type ClientConfig struct {
	APIBase    string
	Timeout    time.Duration
	UserAgent  string
	HTTPClient *http.Client
}

// DefaultClientConfig returns a production-ready default config.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		APIBase: defaultAPIBase,
		Timeout: defaultTimeout,
	}
}

// Client fetches Scorecard runs from the public api.scorecard.dev endpoint.
type Client struct {
	http   *http.Client
	config ClientConfig
}

// NewClient creates a Scorecard HTTP client.
func NewClient(config ClientConfig) *Client {
	if strings.TrimSpace(config.APIBase) == "" {
		config.APIBase = defaultAPIBase
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient, _ = sdk.NewHTTPClient(sdk.HTTPClientConfig{Timeout: config.Timeout})
	}
	return &Client{http: httpClient, config: config}
}

// FetchProject returns the Scorecard run for repo (e.g. "github.com/foo/bar").
// Returns ErrProjectNotScored for HTTP 404 and a wrapped error for any other
// non-2xx status or transport failure.
func (c *Client) FetchProject(ctx context.Context, repo string) (*Project, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, fmt.Errorf("scorecard: empty repository")
	}
	endpoint := strings.TrimRight(c.config.APIBase, "/") + "/projects/" + repo

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("scorecard: build request for %s: %w", repo, err)
	}
	req.Header.Set("Accept", "application/json")
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scorecard: fetch %s: %w", repo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrProjectNotScored
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard: fetch %s: status %d", repo, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB cap per project
	if err != nil {
		return nil, fmt.Errorf("scorecard: read response for %s: %w", repo, err)
	}
	var project Project
	if err := json.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("scorecard: decode response for %s: %w", repo, err)
	}
	return &project, nil
}
