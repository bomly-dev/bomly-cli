package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var (
	githubReleaseAPIBase = "https://api.github.com"
	pluginHTTPClient     *http.Client
)

type githubReleaseResponse struct {
	TagName string               `json:"tag_name"`
	Assets  []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	APIURL             string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubReleaseSpec struct {
	Owner string
	Repo  string
	Tag   string
}

type githubReleaseResolution struct {
	DownloadURL      string
	ExpectedChecksum string
	ArchiveName      string
	ResolvedSource   string
	ChecksumVerified bool
}

func parseGitHubReleaseSource(source string) (githubReleaseSpec, bool) {
	if !strings.HasPrefix(strings.TrimSpace(source), "github:") {
		return githubReleaseSpec{}, false
	}
	trimmed := strings.TrimPrefix(strings.TrimSpace(source), "github:")
	parts := strings.SplitN(trimmed, "@", 2)
	if len(parts) != 2 {
		return githubReleaseSpec{}, false
	}
	repoParts := strings.Split(strings.TrimSpace(parts[0]), "/")
	if len(repoParts) != 2 {
		return githubReleaseSpec{}, false
	}
	spec := githubReleaseSpec{
		Owner: strings.TrimSpace(repoParts[0]),
		Repo:  strings.TrimSpace(repoParts[1]),
		Tag:   strings.TrimSpace(parts[1]),
	}
	if spec.Owner == "" || spec.Repo == "" || spec.Tag == "" {
		return githubReleaseSpec{}, false
	}
	return spec, true
}

func resolveGitHubRelease(ctx context.Context, source string) (githubReleaseResolution, error) {
	spec, ok := parseGitHubReleaseSource(source)
	if !ok {
		return githubReleaseResolution{}, fmt.Errorf("invalid GitHub release source %q", source)
	}
	apiURL := strings.TrimRight(githubReleaseAPIBase, "/") + "/repos/" + url.PathEscape(spec.Owner) + "/" + url.PathEscape(spec.Repo) + "/releases/tags/" + url.PathEscape(spec.Tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return githubReleaseResolution{}, fmt.Errorf("create GitHub release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client, err := githubReleaseHTTPClient(ctx)
	if err != nil {
		return githubReleaseResolution{}, err
	}
	resp, err := githubDoWithAuthFallback(client, req)
	if err != nil {
		return githubReleaseResolution{}, fmt.Errorf("fetch GitHub release metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return githubReleaseResolution{}, fmt.Errorf("fetch GitHub release metadata: unexpected status %s (%s)", resp.Status, redactGitHubSecrets(strings.TrimSpace(string(body))))
	}
	var release githubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return githubReleaseResolution{}, fmt.Errorf("decode GitHub release metadata: %w", err)
	}
	asset, err := selectGitHubReleaseAsset(release.Assets)
	if err != nil {
		return githubReleaseResolution{}, err
	}
	downloadURL := githubReleaseAssetDownloadURL(spec, asset)
	if downloadURL == "" {
		return githubReleaseResolution{}, fmt.Errorf("no GitHub API download endpoint found for asset %q", asset.Name)
	}
	checksum, ok := selectGitHubReleaseChecksum(ctx, spec, asset.Name, release.Assets)
	return githubReleaseResolution{
		DownloadURL:      downloadURL,
		ExpectedChecksum: checksum,
		ArchiveName:      asset.Name,
		ResolvedSource:   source,
		ChecksumVerified: ok,
	}, nil
}

func selectGitHubReleaseAsset(assets []githubReleaseAsset) (githubReleaseAsset, error) {
	wantExt := ".tar.gz"
	if runtime.GOOS == "windows" {
		wantExt = ".zip"
	}
	candidates := make([]githubReleaseAsset, 0)
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if !strings.HasSuffix(name, wantExt) {
			continue
		}
		if assetMatchesPlatform(name) {
			candidates = append(candidates, asset)
		}
	}
	if len(candidates) == 0 {
		return githubReleaseAsset{}, fmt.Errorf("no GitHub release asset matched %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if len(candidates) > 1 {
		for _, candidate := range candidates {
			if strings.Contains(strings.ToLower(candidate.Name), "plugin") {
				return candidate, nil
			}
		}
	}
	return candidates[0], nil
}

func assetMatchesPlatform(name string) bool {
	osTokens := []string{
		runtime.GOOS + "_" + runtime.GOARCH,
		runtime.GOOS + "-" + runtime.GOARCH,
		runtime.GOOS + "/" + runtime.GOARCH,
	}
	for _, token := range osTokens {
		if strings.Contains(name, token) {
			return true
		}
	}
	return strings.Contains(name, runtime.GOOS) && strings.Contains(name, runtime.GOARCH)
}

func selectGitHubReleaseChecksum(ctx context.Context, spec githubReleaseSpec, assetName string, assets []githubReleaseAsset) (string, bool) {
	for _, asset := range assets {
		lower := strings.ToLower(asset.Name)
		if lower != "sha256sums" && lower != "sha256sums.txt" {
			continue
		}
		downloadURL := githubReleaseAssetDownloadURL(spec, asset)
		if strings.TrimSpace(downloadURL) == "" {
			continue
		}
		value, err := fetchChecksumLine(ctx, downloadURL, assetName)
		if err == nil && value != "" {
			return value, true
		}
	}
	return "", false
}

func githubReleaseAssetDownloadURL(spec githubReleaseSpec, asset githubReleaseAsset) string {
	if value := strings.TrimSpace(asset.APIURL); value != "" {
		return value
	}
	if asset.ID > 0 {
		return strings.TrimRight(githubReleaseAPIBase, "/") + "/repos/" + url.PathEscape(spec.Owner) + "/" + url.PathEscape(spec.Repo) + "/releases/assets/" + strconv.FormatInt(asset.ID, 10)
	}
	return strings.TrimSpace(asset.BrowserDownloadURL)
}

func fetchChecksumLine(ctx context.Context, downloadURL, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	client, err := githubReleaseHTTPClient(ctx)
	if err != nil {
		return "", err
	}
	resp, err := githubDoWithAuthFallback(client, req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	baseName := filepath.Base(assetName)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		cleanName := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
		if name == assetName || name == baseName || filepath.Base(cleanName) == baseName {
			return "sha256:" + fields[0], nil
		}
	}
	return "", errors.New("checksum not found")
}

func githubReleaseHTTPClient(ctx context.Context) (*http.Client, error) {
	if pluginHTTPClient != nil {
		return pluginHTTPClient, nil
	}
	return httpClientFromLaunchContext(ctx, 0)
}

// githubDoWithAuthFallback issues req against the GitHub API, attaching the
// configured token when one is present. GitHub rejects an invalid or expired
// token with 401 ("Bad credentials") even for public resources that need no
// auth at all, so a stale token in the environment (a common situation with
// gh, CI helpers, and old dotfiles) would otherwise break installs from public
// repos. When an authenticated request comes back 401 we retry once
// anonymously; token auth still works for private and rate-limited repos.
func githubDoWithAuthFallback(client *http.Client, req *http.Request) (*http.Response, error) {
	applyGitHubAuthHeader(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || req.Header.Get("Authorization") == "" {
		return resp, nil
	}
	_ = resp.Body.Close()
	retry := req.Clone(req.Context())
	retry.Header.Del("Authorization")
	return client.Do(retry)
}

func applyGitHubAuthHeader(req *http.Request) {
	if req == nil {
		return
	}
	token := githubAuthTokenFromEnv()
	if token == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
}

func githubAuthTokenFromEnv() string {
	for _, name := range []string{"BOMLY_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token
		}
	}
	return ""
}

func redactGitHubSecrets(value string) string {
	token := githubAuthTokenFromEnv()
	if token == "" || value == "" {
		return value
	}
	return strings.ReplaceAll(value, token, "[redacted]")
}
