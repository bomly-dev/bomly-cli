package plugin

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/plugin/runtime/hashicorp"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

// Install installs a managed plugin from a local archive, local dev binary, or direct URL.
func Install(ctx context.Context, root, source string, opts InstallOptions) (*InstallResult, error) {
	if root == "" {
		var err error
		root, err = defaultRoot()
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("plugin source is required")
	}
	tempDir, err := os.MkdirTemp("", "bomly-plugin-install-*")
	if err != nil {
		return nil, fmt.Errorf("create plugin install temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	var manifest Manifest
	var checksum string
	resolvedSource := source
	checksumVerified := false
	switch {
	case opts.DevBinary:
		manifest, checksum, err = installDevBinary(ctx, tempDir, source)
		checksumVerified = checksum != ""
	case isGitHubReleaseSource(source):
		manifest, checksum, resolvedSource, checksumVerified, err = installGitHubRelease(ctx, tempDir, source, opts)
	case isRemoteURL(source):
		manifest, checksum, err = installRemoteArchive(ctx, tempDir, source, opts)
		checksumVerified = opts.Checksum != "" || opts.InsecureSkipChecksum
	default:
		manifest, checksum, err = installLocalArtifact(ctx, tempDir, source, opts)
		checksumVerified = checksum != ""
	}
	if err != nil {
		return nil, err
	}

	manifest = withCanonicalManifestDefaults(manifest, source)
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	finalDir := filepath.Join(storeRoot(root), manifest.ID, manifest.Version)
	if err := os.MkdirAll(filepath.Dir(finalDir), 0o755); err != nil {
		return nil, fmt.Errorf("create plugin store parent: %w", err)
	}
	_ = os.RemoveAll(finalDir)
	if err := os.Rename(tempDir, finalDir); err != nil {
		return nil, fmt.Errorf("move plugin into store: %w", err)
	}
	record := InstalledPlugin{
		ID:       manifest.ID,
		Version:  manifest.Version,
		Enabled:  false,
		Source:   source,
		Checksum: checksum,
		Path:     finalDir,
		Runtime:  manifest.Runtime,
		Kind:     manifest.Kind,
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	db = insertInstalledPlugin(db, record)
	if err := saveInstalledDB(root, db); err != nil {
		return nil, err
	}
	return &InstallResult{
		Manifest:         manifest,
		Installed:        record,
		ResolvedSource:   resolvedSource,
		ChecksumVerified: checksumVerified,
	}, nil
}

func installGitHubRelease(ctx context.Context, tempDir, source string, opts InstallOptions) (Manifest, string, string, bool, error) {
	resolution, err := resolveGitHubRelease(ctx, source)
	if err != nil {
		return Manifest{}, "", "", false, err
	}
	expectedChecksum := opts.Checksum
	if expectedChecksum == "" {
		expectedChecksum = resolution.ExpectedChecksum
	}
	manifest, checksum, err := installRemoteArchive(ctx, tempDir, resolution.DownloadURL, InstallOptions{
		Checksum:               expectedChecksum,
		InsecureSkipChecksum:   opts.InsecureSkipChecksum || expectedChecksum == "",
		githubReleaseDownload:  true,
		githubReleaseAssetName: resolution.ArchiveName,
	})
	if err != nil {
		return Manifest{}, "", "", false, err
	}
	return manifest, checksum, resolution.DownloadURL, resolution.ExpectedChecksum != "", nil
}

func installDevBinary(ctx context.Context, tempDir, source string) (Manifest, string, error) {
	binaryPath, err := resolveLocalExecutablePath(source)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("resolve plugin binary path: %w", err)
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("stat plugin binary: %w", err)
	}
	if info.IsDir() {
		return Manifest{}, "", fmt.Errorf("plugin dev binary %q is a directory", source)
	}
	binaryPath, err = normalizeWindowsExecutableForLaunch(tempDir, binaryPath)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("prepare plugin binary for launch: %w", err)
	}
	metadata, err := fetchRuntimeMetadata(ctx, binaryPath)
	if err != nil {
		return Manifest{}, "", err
	}
	detectorDescriptor, packageManagerSupport, matcherDescriptor, auditorDescriptor, err := fetchRuntimeDescriptors(ctx, binaryPath, metadata.Kind, metadata.ID)
	if err != nil {
		return Manifest{}, "", err
	}
	manifest, err := manifestFromMetadata(metadata, detectorDescriptor, packageManagerSupport, matcherDescriptor, auditorDescriptor, source, filepath.Base(binaryPath))
	if err != nil {
		return Manifest{}, "", err
	}
	entry, _ := entrypointForManifest(manifest)
	targetBinary := filepath.Join(tempDir, entry)
	if err := os.MkdirAll(filepath.Dir(targetBinary), 0o755); err != nil {
		return Manifest{}, "", fmt.Errorf("create plugin binary dir: %w", err)
	}
	if err := copyFile(targetBinary, binaryPath, 0o755); err != nil {
		return Manifest{}, "", fmt.Errorf("copy plugin binary: %w", err)
	}
	if err := writeManifest(tempDir, manifest); err != nil {
		return Manifest{}, "", err
	}
	checksum, err := checksumFile(binaryPath)
	if err != nil {
		return Manifest{}, "", err
	}
	return manifest, checksum, nil
}

func installRemoteArchive(ctx context.Context, tempDir, source string, opts InstallOptions) (Manifest, string, error) {
	if opts.Checksum == "" && !opts.InsecureSkipChecksum {
		return Manifest{}, "", errors.New("direct URL plugin installs require --checksum or --insecure-skip-checksum")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("create plugin download request: %w", err)
	}
	if opts.githubReleaseDownload {
		req.Header.Set("Accept", "application/octet-stream")
		applyGitHubAuthHeader(req)
	}
	client, err := httpClientFromLaunchContext(ctx, 0)
	if err != nil {
		return Manifest{}, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("download plugin archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Manifest{}, "", fmt.Errorf("download plugin archive: unexpected status %s", resp.Status)
	}
	downloadName := strings.TrimSpace(opts.githubReleaseAssetName)
	if downloadName == "" {
		downloadName = filenameFromContentDisposition(resp.Header.Get("Content-Disposition"))
	}
	if downloadName == "" {
		downloadName = filepath.Base(resp.Request.URL.Path)
	}
	if strings.TrimSpace(downloadName) == "" || downloadName == "." || downloadName == "/" {
		downloadName = "downloaded-plugin"
	}
	archivePath := filepath.Join(filepath.Dir(tempDir), downloadName)
	file, err := os.Create(archivePath)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("create downloaded plugin archive: %w", err)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		_ = file.Close()
		return Manifest{}, "", fmt.Errorf("write downloaded plugin archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return Manifest{}, "", fmt.Errorf("close downloaded plugin archive: %w", err)
	}
	return installArchiveAtPath(ctx, tempDir, archivePath, source, opts.Checksum, opts.InsecureSkipChecksum)
}

func filenameFromContentDisposition(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	if name := strings.TrimSpace(params["filename"]); name != "" {
		return filepath.Base(name)
	}
	return ""
}

func installLocalArtifact(ctx context.Context, tempDir, source string, opts InstallOptions) (Manifest, string, error) {
	artifactPath, err := filepath.Abs(source)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("resolve plugin source path: %w", err)
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("stat plugin source: %w", err)
	}
	if info.IsDir() {
		return Manifest{}, "", fmt.Errorf("plugin source %q is a directory", source)
	}
	return installArchiveAtPath(ctx, tempDir, artifactPath, source, opts.Checksum, opts.InsecureSkipChecksum)
}

func installArchiveAtPath(ctx context.Context, tempDir, archivePath, source, expectedChecksum string, skipChecksum bool) (Manifest, string, error) {
	checksum, err := checksumFile(archivePath)
	if err != nil {
		return Manifest{}, "", err
	}
	if expectedChecksum != "" && checksum != expectedChecksum {
		return Manifest{}, "", fmt.Errorf("plugin checksum mismatch: expected %s, got %s", expectedChecksum, checksum)
	}
	if !skipChecksum && expectedChecksum == "" && isRemoteURL(source) {
		return Manifest{}, "", errors.New("plugin checksum is required for URL installs")
	}
	if err := extractArchive(archivePath, tempDir); err != nil {
		return Manifest{}, "", err
	}
	manifest, err := readManifest(tempDir)
	if err != nil {
		return Manifest{}, "", err
	}
	entry, err := entrypointForManifest(manifest)
	if err != nil {
		return Manifest{}, "", err
	}
	fullEntrypoint := filepath.Join(tempDir, entry)
	if _, err := os.Stat(fullEntrypoint); err != nil {
		return Manifest{}, "", fmt.Errorf("plugin entrypoint %q is missing: %w", entry, err)
	}
	metadata, err := fetchRuntimeMetadata(ctx, fullEntrypoint, manifest.ID)
	if err != nil {
		return Manifest{}, "", err
	}
	detectorDescriptor, packageManagerSupport, matcherDescriptor, auditorDescriptor, err := fetchRuntimeDescriptors(ctx, fullEntrypoint, metadata.Kind, metadata.ID)
	if err != nil {
		return Manifest{}, "", err
	}
	manifest = withCanonicalManifestDefaults(manifest, source)
	manifest = manifestWithRuntimeContract(manifest, metadata, detectorDescriptor, packageManagerSupport, matcherDescriptor, auditorDescriptor)
	if err := runtimeMetadataMatchesManifest(metadata, detectorDescriptor, packageManagerSupport, matcherDescriptor, auditorDescriptor, manifest); err != nil {
		return Manifest{}, "", err
	}
	if err := writeManifest(tempDir, manifest); err != nil {
		return Manifest{}, "", err
	}
	return manifest, checksum, nil
}

func extractArchive(archivePath, targetDir string) error {
	switch {
	case strings.HasSuffix(strings.ToLower(archivePath), ".zip"):
		return extractZipArchive(archivePath, targetDir)
	case strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz"), strings.HasSuffix(strings.ToLower(archivePath), ".tgz"):
		return extractTarGzArchive(archivePath, targetDir)
	default:
		return fmt.Errorf("unsupported plugin archive format for %q", archivePath)
	}
}

func extractZipArchive(archivePath, targetDir string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open plugin zip archive: %w", err)
	}
	defer func() { _ = reader.Close() }()
	for _, file := range reader.File {
		if err := extractArchiveEntry(file.Name, targetDir, file.Mode(), func(dst string) error {
			if file.FileInfo().IsDir() {
				return os.MkdirAll(dst, 0o755)
			}
			rc, err := file.Open()
			if err != nil {
				return fmt.Errorf("open archive file %q: %w", file.Name, err)
			}
			defer func() { _ = rc.Close() }()
			return writeArchiveFile(dst, rc, file.Mode())
		}); err != nil {
			return err
		}
	}
	return nil
}

func extractTarGzArchive(archivePath, targetDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open plugin tar.gz archive: %w", err)
	}
	defer func() { _ = file.Close() }()
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open plugin gzip stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read plugin tar entry: %w", err)
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("plugin archive entry %q uses unsupported type", header.Name)
		}
		if err := extractArchiveEntry(header.Name, targetDir, os.FileMode(header.Mode), func(dst string) error {
			if header.FileInfo().IsDir() {
				return os.MkdirAll(dst, 0o755)
			}
			return writeArchiveFile(dst, tr, os.FileMode(header.Mode))
		}); err != nil {
			return err
		}
	}
}

func extractArchiveEntry(name, targetDir string, mode os.FileMode, write func(string) error) error {
	cleanName := filepath.Clean(filepath.FromSlash(strings.TrimSpace(name)))
	if cleanName == "." || cleanName == "" {
		return nil
	}
	if filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, "..") {
		return fmt.Errorf("plugin archive entry %q escapes the extraction directory", name)
	}
	destination := filepath.Join(targetDir, cleanName)
	rel, err := filepath.Rel(targetDir, destination)
	if err != nil {
		return fmt.Errorf("resolve plugin archive entry %q: %w", name, err)
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("plugin archive entry %q escapes the extraction directory", name)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create plugin archive parent for %q: %w", name, err)
	}
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin archive entry %q uses unsupported symlink mode", name)
	}
	return write(destination)
}

func writeArchiveFile(path string, reader io.Reader, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("create plugin archive file %q: %w", path, err)
	}
	if _, err := io.Copy(file, reader); err != nil {
		_ = file.Close()
		return fmt.Errorf("write plugin archive file %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close plugin archive file %q: %w", path, err)
	}
	return nil
}

func isRemoteURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func isGitHubReleaseSource(raw string) bool {
	_, ok := parseGitHubReleaseSource(raw)
	return ok
}

func copyFile(dst, src string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func resolveLocalExecutablePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" && filepath.Ext(absPath) == "" {
		windowsPath := absPath + ".exe"
		if _, statErr := os.Stat(windowsPath); statErr == nil {
			return windowsPath, nil
		}
	}
	if _, statErr := os.Stat(absPath); statErr == nil {
		return absPath, nil
	}
	return absPath, nil
}

func normalizeWindowsExecutableForLaunch(tempDir, binaryPath string) (string, error) {
	if runtime.GOOS != "windows" || filepath.Ext(binaryPath) != "" {
		return binaryPath, nil
	}
	if _, err := os.Stat(binaryPath); err != nil {
		return binaryPath, err
	}
	launchPath := filepath.Join(tempDir, filepath.Base(binaryPath)+".exe")
	if err := copyFile(launchPath, binaryPath, 0o755); err != nil {
		return "", err
	}
	return launchPath, nil
}

func fetchRuntimeMetadata(ctx context.Context, executable string, pluginID ...string) (*plugschema.PluginMetadata, error) {
	client, err := startPlugin(ctx, executable, firstString(pluginID))
	if err != nil {
		return nil, err
	}
	defer client.Close()
	metadata, err := client.Raw().Metadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("query plugin metadata: %w", err)
	}
	return metadata, nil
}

func fetchRuntimeDescriptors(ctx context.Context, executable string, kind plugschema.PluginKind, pluginID ...string) (*plugschema.DetectorDescriptor, []plugschema.PackageManagerSupport, *plugschema.MatcherDescriptor, *plugschema.AuditorDescriptor, error) {
	client, err := startPlugin(ctx, executable, firstString(pluginID))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer client.Close()

	switch kind {
	case plugschema.PluginKindDetector:
		descriptor, err := client.Raw().DetectorDescriptor(ctx)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		support, err := client.Raw().DetectorPackageManagerSupport(ctx)
		return descriptor, support, nil, nil, err
	case plugschema.PluginKindMatcher:
		descriptor, err := client.Raw().MatcherDescriptor(ctx)
		return nil, nil, descriptor, nil, err
	case plugschema.PluginKindAuditor:
		descriptor, err := client.Raw().AuditorDescriptor(ctx)
		return nil, nil, nil, descriptor, err
	default:
		return nil, nil, nil, nil, fmt.Errorf("unsupported plugin kind %q", kind)
	}
}

type runtimeClient struct {
	client  *hashicorp.Client
	cleanup func()
}

func (c *runtimeClient) Raw() plugschema.Client {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Raw()
}

func (c *runtimeClient) Close() {
	if c == nil {
		return
	}
	if c.client != nil {
		c.client.Close()
	}
	if c.cleanup != nil {
		c.cleanup()
	}
}

func startPlugin(ctx context.Context, executable, pluginID string) (*runtimeClient, error) {
	options, _ := LaunchOptionsFromContext(ctx)
	env, cleanup, err := pluginEnv(options, pluginID)
	if err != nil {
		return nil, err
	}
	client, err := hashicorp.Start(ctx, executable, env, options.Verbosity)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &runtimeClient{client: client, cleanup: cleanup}, nil
}

func pluginEnv(options LaunchOptions, pluginID string) ([]string, func(), error) {
	env := []string{
		EnvPluginAPIVersion + "=" + plugschema.PluginAPIVersion,
		EnvPluginConfig + "=" + strings.TrimSpace(options.ConfigPath),
	}
	if strings.TrimSpace(pluginID) != "" {
		env = append(env, plugschema.EnvPluginID+"="+strings.TrimSpace(pluginID))
	}
	env = append(env, proxyEnv(options)...)
	cleanup := func() {}
	if config, ok := options.PluginConfigs[strings.TrimSpace(pluginID)]; ok && config != nil {
		path, remove, err := writePluginConfigFile(config)
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = remove
		env = append(env, plugschema.EnvPluginConfigFile+"="+path)
	}
	return env, cleanup, nil
}

func proxyEnv(options LaunchOptions) []string {
	env := make([]string, 0, 8)
	proxyConfig := launchHTTPConfig(options, 0)
	proxy, err := proxyConfig.EffectiveProxyURL()
	if err == nil && strings.TrimSpace(proxy) != "" {
		env = append(env,
			plugschema.EnvHTTPProxy+"="+proxy,
			"HTTP_PROXY="+proxy,
			"HTTPS_PROXY="+proxy,
			"http_proxy="+proxy,
			"https_proxy="+proxy,
		)
	} else {
		env = appendExistingEnv(env, "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
	}
	if noProxy := strings.TrimSpace(proxyConfig.NoProxy); noProxy != "" {
		env = append(env,
			plugschema.EnvHTTPNoProxy+"="+noProxy,
			"NO_PROXY="+noProxy,
			"no_proxy="+noProxy,
		)
	} else {
		env = appendExistingEnv(env, "NO_PROXY", "no_proxy")
	}
	env = appendProxyConfigEnv(env, options)
	return env
}

func appendProxyConfigEnv(env []string, options LaunchOptions) []string {
	if value := strings.TrimSpace(options.HTTPProxyType); value != "" {
		env = append(env, plugschema.EnvHTTPProxyType+"="+value)
	}
	if value := strings.TrimSpace(options.HTTPProxyHost); value != "" {
		env = append(env, plugschema.EnvHTTPProxyHost+"="+value)
	}
	if options.HTTPProxyPort > 0 {
		env = append(env, plugschema.EnvHTTPProxyPort+"="+strconv.Itoa(options.HTTPProxyPort))
	}
	if value := strings.TrimSpace(options.HTTPProxyUsername); value != "" {
		env = append(env, plugschema.EnvHTTPProxyUsername+"="+value)
	}
	if options.HTTPProxyPassword != "" {
		env = append(env, plugschema.EnvHTTPProxyPassword+"="+options.HTTPProxyPassword)
	}
	if value := strings.TrimSpace(options.HTTPCACertFile); value != "" {
		env = append(env, plugschema.EnvHTTPCACertFile+"="+value)
	}
	return env
}

func appendExistingEnv(env []string, names ...string) []string {
	for _, name := range names {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		env = append(env, name+"="+value)
	}
	return env
}

func writePluginConfigFile(config map[string]any) (string, func(), error) {
	file, err := os.CreateTemp("", "bomly-plugin-config-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("create plugin config file: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("encode plugin config file: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close plugin config file: %w", err)
	}
	return path, cleanup, nil
}

func httpClientFromLaunchContext(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	options, _ := LaunchOptionsFromContext(ctx)
	if options.HTTPClientProvider != nil {
		return options.HTTPClientProvider.Client(timeout), nil
	}
	provider, err := plugschema.NewHTTPClientProvider(launchHTTPConfig(options, 0))
	if err != nil {
		return nil, err
	}
	return provider.Client(timeout), nil
}

func launchHTTPConfig(options LaunchOptions, timeout time.Duration) plugschema.HTTPClientConfig {
	return plugschema.HTTPClientConfig{
		ProxyURL:      options.HTTPProxy,
		NoProxy:       options.HTTPNoProxy,
		ProxyType:     options.HTTPProxyType,
		ProxyHost:     options.HTTPProxyHost,
		ProxyPort:     options.HTTPProxyPort,
		ProxyUsername: options.HTTPProxyUsername,
		ProxyPassword: options.HTTPProxyPassword,
		CACertFile:    options.HTTPCACertFile,
		Timeout:       timeout,
	}
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
