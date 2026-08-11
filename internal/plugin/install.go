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
	plugschema "github.com/bomly-dev/bomly-sdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// Plugin archives contain one native executable plus a small manifest and
	// supporting files. These limits allow large statically linked binaries
	// without allowing an archive to consume unbounded local resources.
	maxPluginDownloadBytes        int64 = 256 << 20
	maxPluginArchiveEntries             = 4096
	maxPluginArchiveEntryBytes    int64 = 256 << 20
	maxPluginArchiveExpandedBytes int64 = 512 << 20
)

type archiveLimits struct {
	maxEntries       int
	maxEntryBytes    int64
	maxExpandedBytes int64
}

func defaultArchiveLimits() archiveLimits {
	return archiveLimits{
		maxEntries:       maxPluginArchiveEntries,
		maxEntryBytes:    maxPluginArchiveEntryBytes,
		maxExpandedBytes: maxPluginArchiveExpandedBytes,
	}
}

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
	snapshot, err := discoverRuntimeSnapshot(ctx, binaryPath)
	if err != nil {
		return Manifest{}, "", err
	}
	manifest, err := manifestFromRuntimeSnapshot(snapshot, source, filepath.Base(binaryPath))
	if err != nil {
		return Manifest{}, "", err
	}
	entry, _ := entrypointForManifest(manifest)
	targetBinary, err := pathInPluginDir(tempDir, entry)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	if err := os.MkdirAll(filepath.Dir(targetBinary), 0o755); err != nil {
		return Manifest{}, "", fmt.Errorf("create plugin binary dir: %w", err)
	}
	if err := copyFile(targetBinary, binaryPath, 0o755); err != nil {
		return Manifest{}, "", fmt.Errorf("copy plugin binary: %w", err)
	}
	if err := writeManifest(tempDir, manifest); err != nil {
		return Manifest{}, "", err
	}
	if err := writeRuntimeSnapshot(tempDir, snapshot); err != nil {
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
	client, err := httpClientFromLaunchContext(ctx, 0)
	if err != nil {
		return Manifest{}, "", err
	}
	var resp *http.Response
	if opts.githubReleaseDownload {
		req.Header.Set("Accept", "application/octet-stream")
		resp, err = githubDoWithAuthFallback(client, req)
	} else {
		resp, err = client.Do(req)
	}
	if err != nil {
		return Manifest{}, "", fmt.Errorf("download plugin archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Manifest{}, "", fmt.Errorf("download plugin archive: unexpected status %s", resp.Status)
	}
	if err := validateDownloadContentLength(resp.ContentLength, maxPluginDownloadBytes); err != nil {
		return Manifest{}, "", fmt.Errorf("download plugin archive: %w", err)
	}
	downloadName := strings.TrimSpace(opts.githubReleaseAssetName)
	if downloadName == "" {
		downloadName = filenameFromContentDisposition(resp.Header.Get("Content-Disposition"))
	}
	if downloadName == "" {
		downloadName = filepath.Base(resp.Request.URL.Path)
	}
	downloadName = safeDownloadArchiveName(downloadName)
	if downloadName == "" {
		downloadName = "downloaded-plugin"
	}
	file, err := os.CreateTemp(filepath.Dir(tempDir), "bomly-plugin-archive-*"+archiveExtension(downloadName))
	if err != nil {
		return Manifest{}, "", fmt.Errorf("create downloaded plugin archive: %w", err)
	}
	archivePath := file.Name()
	defer func() { _ = os.Remove(archivePath) }()
	if _, err := copyDownloadWithLimit(file, resp.Body, resp.ContentLength, maxPluginDownloadBytes); err != nil {
		_ = file.Close()
		return Manifest{}, "", fmt.Errorf("write downloaded plugin archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return Manifest{}, "", fmt.Errorf("close downloaded plugin archive: %w", err)
	}
	return installArchiveAtPath(ctx, tempDir, archivePath, source, opts.Checksum, opts.InsecureSkipChecksum)
}

func copyDownloadWithLimit(dst io.Writer, src io.Reader, contentLength, limit int64) (int64, error) {
	if err := validateDownloadContentLength(contentLength, limit); err != nil {
		return 0, err
	}
	written, err := io.CopyN(dst, src, limit)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return written, nil
		}
		return written, fmt.Errorf("read plugin archive download: %w", err)
	}
	var probe [1]byte
	count, probeErr := src.Read(probe[:])
	if count > 0 {
		return written, fmt.Errorf("plugin archive download exceeds the %d-byte limit", limit)
	}
	if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		return written, fmt.Errorf("read plugin archive download: %w", probeErr)
	}
	return written, nil
}

func validateDownloadContentLength(contentLength, limit int64) error {
	if contentLength > limit {
		return fmt.Errorf("plugin archive download exceeds the %d-byte limit", limit)
	}
	return nil
}

func safeDownloadArchiveName(name string) string {
	// Remote archive names are only used to preserve a trusted extension for temp-file format detection.
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return ""
	}
	base := filepath.Base(filepath.FromSlash(name))
	if base == "." || base == string(os.PathSeparator) || base == ".." || strings.Contains(base, ":") {
		return ""
	}
	return base
}

func archiveExtension(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(lower, ".tgz"):
		return ".tgz"
	case strings.HasSuffix(lower, ".zip"):
		return ".zip"
	default:
		return ""
	}
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
		return safeDownloadArchiveName(name)
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
	archiveChecksum, err := checksumFile(archivePath)
	if err != nil {
		return Manifest{}, "", err
	}
	if expectedChecksum != "" && archiveChecksum != expectedChecksum {
		return Manifest{}, "", fmt.Errorf("plugin checksum mismatch: expected %s, got %s", expectedChecksum, archiveChecksum)
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
	fullEntrypoint, err := pathInPluginDir(tempDir, entry)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	if _, err := os.Stat(fullEntrypoint); err != nil {
		return Manifest{}, "", fmt.Errorf("plugin entrypoint %q is missing: %w", entry, err)
	}
	manifest = withCanonicalManifestDefaults(manifest, source)
	snapshot, err := fetchRuntimeSnapshot(ctx, fullEntrypoint, manifest.Kind, manifest.ID)
	if err != nil {
		return Manifest{}, "", err
	}
	if err := runtimeSnapshotMatchesManifest(snapshot, manifest); err != nil {
		return Manifest{}, "", err
	}
	if err := writeManifest(tempDir, manifest); err != nil {
		return Manifest{}, "", err
	}
	if err := writeRuntimeSnapshot(tempDir, snapshot); err != nil {
		return Manifest{}, "", err
	}
	entrypointChecksum, err := checksumFile(fullEntrypoint)
	if err != nil {
		return Manifest{}, "", err
	}
	return manifest, entrypointChecksum, nil
}

func extractArchive(archivePath, targetDir string) error {
	limits := defaultArchiveLimits()
	switch {
	case strings.HasSuffix(strings.ToLower(archivePath), ".zip"):
		return extractZipArchive(archivePath, targetDir, limits)
	case strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz"), strings.HasSuffix(strings.ToLower(archivePath), ".tgz"):
		return extractTarGzArchive(archivePath, targetDir, limits)
	default:
		return fmt.Errorf("unsupported plugin archive format for %q", archivePath)
	}
}

func extractZipArchive(archivePath, targetDir string, limits archiveLimits) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open plugin zip archive: %w", err)
	}
	defer func() { _ = reader.Close() }()
	if err := validateZipArchiveLimits(reader.File, limits); err != nil {
		return err
	}
	budget := newArchiveExtractionBudget(limits)
	for _, file := range reader.File {
		// Inline locality guard: rejects traversal without rejecting legitimate
		// dotted filenames; recognized by static analyzers as a sanitizer.
		if !filepath.IsLocal(file.Name) {
			return fmt.Errorf("plugin archive entry %q escapes the extraction directory", file.Name)
		}
		if err := validateArchiveEntryName(file.Name); err != nil {
			return err
		}
		if err := budget.beginEntry(file.Name, file.UncompressedSize64); err != nil {
			return err
		}
		expanded, err := extractArchiveEntry(file.Name, targetDir, file.Mode(), func(dst string) (int64, error) {
			if file.FileInfo().IsDir() {
				return 0, os.MkdirAll(dst, 0o755)
			}
			rc, err := file.Open()
			if err != nil {
				return 0, fmt.Errorf("open archive file %q: %w", file.Name, err)
			}
			defer func() { _ = rc.Close() }()
			return writeArchiveFile(dst, rc, file.Mode(), file.Name, budget)
		})
		if err != nil {
			return err
		}
		if err := budget.addExpanded(file.Name, expanded); err != nil {
			return err
		}
	}
	return nil
}

func validateZipArchiveLimits(files []*zip.File, limits archiveLimits) error {
	if len(files) > limits.maxEntries {
		return fmt.Errorf("plugin archive contains %d entries; limit is %d", len(files), limits.maxEntries)
	}
	// ZIP sizes are untrusted metadata and only provide an early rejection.
	// writeArchiveFile and archiveExtractionBudget enforce the real byte stream.
	var expanded uint64
	for _, file := range files {
		size := file.UncompressedSize64
		if size > uint64(limits.maxEntryBytes) {
			return fmt.Errorf("plugin archive entry %q exceeds the %d-byte expanded size limit", file.Name, limits.maxEntryBytes)
		}
		if size > uint64(limits.maxExpandedBytes)-expanded {
			return fmt.Errorf("plugin archive expanded size exceeds the %d-byte limit", limits.maxExpandedBytes)
		}
		expanded += size
	}
	return nil
}

func extractTarGzArchive(archivePath, targetDir string, limits archiveLimits) error {
	cleanArchivePath, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("resolve plugin tar.gz archive: %w", err)
	}
	file, err := os.Open(cleanArchivePath)
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
	budget := newArchiveExtractionBudget(limits)
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
		if header.Size < 0 {
			return fmt.Errorf("plugin archive entry %q has a negative size", header.Name)
		}
		// Inline locality guard: rejects traversal without rejecting legitimate
		// dotted filenames; recognized by static analyzers as a sanitizer.
		if !filepath.IsLocal(header.Name) {
			return fmt.Errorf("plugin archive entry %q escapes the extraction directory", header.Name)
		}
		if err := validateArchiveEntryName(header.Name); err != nil {
			return err
		}
		if err := budget.beginEntry(header.Name, uint64(header.Size)); err != nil {
			return err
		}
		expanded, err := extractArchiveEntry(header.Name, targetDir, os.FileMode(header.Mode), func(dst string) (int64, error) {
			if header.FileInfo().IsDir() {
				return 0, os.MkdirAll(dst, 0o755)
			}
			return writeArchiveFile(dst, tr, os.FileMode(header.Mode), header.Name, budget)
		})
		if err != nil {
			return err
		}
		if err := budget.addExpanded(header.Name, expanded); err != nil {
			return err
		}
	}
}

type archiveExtractionBudget struct {
	limits   archiveLimits
	entries  int
	expanded int64
}

func newArchiveExtractionBudget(limits archiveLimits) *archiveExtractionBudget {
	return &archiveExtractionBudget{limits: limits}
}

func (b *archiveExtractionBudget) beginEntry(name string, declaredSize uint64) error {
	b.entries++
	if b.entries > b.limits.maxEntries {
		return fmt.Errorf("plugin archive contains more than %d entries", b.limits.maxEntries)
	}
	if declaredSize > uint64(b.limits.maxEntryBytes) {
		return fmt.Errorf("plugin archive entry %q exceeds the %d-byte expanded size limit", name, b.limits.maxEntryBytes)
	}
	if declaredSize > uint64(b.limits.maxExpandedBytes-b.expanded) {
		return fmt.Errorf("plugin archive expanded size exceeds the %d-byte limit", b.limits.maxExpandedBytes)
	}
	return nil
}

func (b *archiveExtractionBudget) writeLimit() int64 {
	remaining := b.limits.maxExpandedBytes - b.expanded
	if remaining < b.limits.maxEntryBytes {
		return remaining
	}
	return b.limits.maxEntryBytes
}

// overrunError attributes a stream overrun to the limit that actually bounded
// the write: the per-entry cap normally, or the total expanded-size budget
// when less of it remains than one entry may use.
func (b *archiveExtractionBudget) overrunError(name string) error {
	if b.limits.maxExpandedBytes-b.expanded < b.limits.maxEntryBytes {
		return fmt.Errorf("plugin archive expanded size exceeds the %d-byte limit", b.limits.maxExpandedBytes)
	}
	return fmt.Errorf("plugin archive entry %q exceeds the %d-byte expanded size limit", name, b.limits.maxEntryBytes)
}

func (b *archiveExtractionBudget) addExpanded(name string, size int64) error {
	if size < 0 || size > b.writeLimit() {
		return fmt.Errorf("plugin archive entry %q exceeds the extraction limits", name)
	}
	b.expanded += size
	return nil
}

// validateArchiveEntryName rejects archive entry names that could escape the
// extraction directory. It runs on the raw entry name before any filesystem
// path is derived from it: absolute paths, parent-directory (`..`) components,
// and any name filepath.IsLocal considers non-local are all rejected.
func validateArchiveEntryName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || trimmed == "." {
		// Empty and "." entries are ignored by extractArchiveEntry.
		return nil
	}
	slashName := strings.ReplaceAll(trimmed, "\\", "/")
	if strings.HasPrefix(slashName, "/") {
		return fmt.Errorf("plugin archive entry %q uses an absolute path", name)
	}
	// Reject Windows drive and volume syntax regardless of host platform, the
	// same way cleanRelativePluginPath does.
	if strings.Contains(slashName, ":") {
		return fmt.Errorf("plugin archive entry %q uses an absolute path", name)
	}
	for _, part := range strings.Split(slashName, "/") {
		if part == ".." {
			return fmt.Errorf("plugin archive entry %q contains a parent-directory component", name)
		}
	}
	// Directory entries carry a trailing separator; trim it so the local-path
	// check sees the directory name itself.
	localCandidate := filepath.FromSlash(strings.TrimRight(slashName, "/"))
	if localCandidate == "" || !filepath.IsLocal(localCandidate) {
		return fmt.Errorf("plugin archive entry %q escapes the extraction directory", name)
	}
	return nil
}

func extractArchiveEntry(name, targetDir string, mode os.FileMode, write func(string) (int64, error)) (int64, error) {
	if err := validateArchiveEntryName(name); err != nil {
		return 0, err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) == "." {
		return 0, nil
	}
	destination, err := pathInPluginDir(targetDir, name)
	if err != nil {
		return 0, fmt.Errorf("plugin archive entry %q escapes the extraction directory", name)
	}
	rel, err := filepath.Rel(targetDir, destination)
	if err != nil {
		return 0, fmt.Errorf("resolve plugin archive entry %q: %w", name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return 0, fmt.Errorf("plugin archive entry %q escapes the extraction directory", name)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return 0, fmt.Errorf("create plugin archive parent for %q: %w", name, err)
	}
	// Symlinks would make the lexical containment checks above vulnerable to writes outside targetDir.
	if mode&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("plugin archive entry %q uses unsupported symlink mode", name)
	}
	return write(destination)
}

func writeArchiveFile(path string, reader io.Reader, mode os.FileMode, entryName string, budget *archiveExtractionBudget) (int64, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return 0, fmt.Errorf("create plugin archive file %q: %w", path, err)
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	written, err := io.CopyN(file, reader, budget.writeLimit())
	if err != nil && !errors.Is(err, io.EOF) {
		return written, fmt.Errorf("write plugin archive file %q: %w", path, err)
	}
	if err == nil {
		var probe [1]byte
		count, probeErr := reader.Read(probe[:])
		if count > 0 {
			return written, budget.overrunError(entryName)
		}
		if probeErr != nil && !errors.Is(probeErr, io.EOF) {
			return written, fmt.Errorf("write plugin archive file %q: %w", path, probeErr)
		}
	}
	if err := file.Close(); err != nil {
		return written, fmt.Errorf("close plugin archive file %q: %w", path, err)
	}
	removePartial = false
	return written, nil
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

func discoverRuntimeSnapshot(ctx context.Context, executable string) (RuntimeDescriptorSnapshot, error) {
	client, err := startPlugin(ctx, executable, "", "")
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	defer client.Close()
	var snapshots []RuntimeDescriptorSnapshot
	if snapshot, err := detectorSnapshot(ctx, client.Raw()); err == nil {
		snapshots = append(snapshots, snapshot)
	} else if !isUnimplemented(err) {
		return RuntimeDescriptorSnapshot{}, err
	}
	if snapshot, err := matcherSnapshot(ctx, client.Raw()); err == nil {
		snapshots = append(snapshots, snapshot)
	} else if !isUnimplemented(err) {
		return RuntimeDescriptorSnapshot{}, err
	}
	if snapshot, err := auditorSnapshot(ctx, client.Raw()); err == nil {
		snapshots = append(snapshots, snapshot)
	} else if !isUnimplemented(err) {
		return RuntimeDescriptorSnapshot{}, err
	}
	if snapshot, err := analyzerSnapshot(ctx, client.Raw()); err == nil {
		snapshots = append(snapshots, snapshot)
	} else if !isUnimplemented(err) {
		return RuntimeDescriptorSnapshot{}, err
	}
	switch len(snapshots) {
	case 0:
		return RuntimeDescriptorSnapshot{}, errors.New("plugin dev binary does not serve a detector, matcher, auditor, or analyzer descriptor")
	case 1:
		return normalizeRuntimeSnapshot(snapshots[0]), nil
	default:
		return RuntimeDescriptorSnapshot{}, errors.New("plugin dev binary serves multiple component roles; one package must serve exactly one role")
	}
}

func fetchRuntimeSnapshot(ctx context.Context, executable string, kind plugschema.PluginKind, pluginID ...string) (RuntimeDescriptorSnapshot, error) {
	client, err := startPlugin(ctx, executable, firstString(pluginID), kind)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	defer client.Close()

	switch kind {
	case plugschema.PluginKindDetector:
		return detectorSnapshot(ctx, client.Raw())
	case plugschema.PluginKindMatcher:
		return matcherSnapshot(ctx, client.Raw())
	case plugschema.PluginKindAuditor:
		return auditorSnapshot(ctx, client.Raw())
	case plugschema.PluginKindAnalyzer:
		return analyzerSnapshot(ctx, client.Raw())
	default:
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("unsupported plugin kind %q", kind)
	}
}

func detectorSnapshot(ctx context.Context, client plugschema.Client) (RuntimeDescriptorSnapshot, error) {
	descriptor, err := client.DetectorDescriptor(ctx)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	support, err := client.DetectorPackageManagerSupport(ctx)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	descriptor = cloneDetectorDescriptorWithSupport(descriptor, support)
	if descriptor == nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("detector plugin returned an empty descriptor")
	}
	return normalizeRuntimeSnapshot(RuntimeDescriptorSnapshot{
		SchemaVersion:      plugschema.RuntimeDescriptorSnapshotSchemaVersion,
		ID:                 descriptor.Name,
		Kind:               plugschema.PluginKindDetector,
		PluginAPIVersion:   plugschema.PluginAPIVersion,
		DetectorDescriptor: descriptor,
	}), nil
}

func matcherSnapshot(ctx context.Context, client plugschema.Client) (RuntimeDescriptorSnapshot, error) {
	descriptor, err := client.MatcherDescriptor(ctx)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	if descriptor == nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("matcher plugin returned an empty descriptor")
	}
	return normalizeRuntimeSnapshot(RuntimeDescriptorSnapshot{
		SchemaVersion:     plugschema.RuntimeDescriptorSnapshotSchemaVersion,
		ID:                descriptor.Name,
		Kind:              plugschema.PluginKindMatcher,
		PluginAPIVersion:  plugschema.PluginAPIVersion,
		MatcherDescriptor: cloneMatcherDescriptor(descriptor),
	}), nil
}

func auditorSnapshot(ctx context.Context, client plugschema.Client) (RuntimeDescriptorSnapshot, error) {
	descriptor, err := client.AuditorDescriptor(ctx)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	if descriptor == nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("auditor plugin returned an empty descriptor")
	}
	return normalizeRuntimeSnapshot(RuntimeDescriptorSnapshot{
		SchemaVersion:     plugschema.RuntimeDescriptorSnapshotSchemaVersion,
		ID:                descriptor.Name,
		Kind:              plugschema.PluginKindAuditor,
		PluginAPIVersion:  plugschema.PluginAPIVersion,
		AuditorDescriptor: cloneAuditorDescriptor(descriptor),
	}), nil
}

func analyzerSnapshot(ctx context.Context, client plugschema.Client) (RuntimeDescriptorSnapshot, error) {
	descriptor, err := client.AnalyzerDescriptor(ctx)
	if err != nil {
		return RuntimeDescriptorSnapshot{}, err
	}
	if descriptor == nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("analyzer plugin returned an empty descriptor")
	}
	return normalizeRuntimeSnapshot(RuntimeDescriptorSnapshot{
		SchemaVersion:      plugschema.RuntimeDescriptorSnapshotSchemaVersion,
		ID:                 descriptor.Name,
		Kind:               plugschema.PluginKindAnalyzer,
		PluginAPIVersion:   plugschema.PluginAPIVersion,
		AnalyzerDescriptor: cloneAnalyzerDescriptor(descriptor),
	}), nil
}

func isUnimplemented(err error) bool {
	return status.Code(err) == codes.Unimplemented
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

// Exited reports whether the underlying plugin subprocess has terminated.
func (c *runtimeClient) Exited() bool {
	if c == nil || c.client == nil {
		return true
	}
	return c.client.Exited()
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

func startPlugin(ctx context.Context, executable, pluginID string, kind plugschema.PluginKind) (*runtimeClient, error) {
	options, _ := LaunchOptionsFromContext(ctx)
	env, cleanup, err := pluginEnv(options, pluginID, kind)
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

func pluginEnv(options LaunchOptions, pluginID string, kind plugschema.PluginKind) ([]string, func(), error) {
	env := []string{
		EnvPluginAPIVersion + "=" + plugschema.PluginAPIVersion,
		EnvPluginConfig + "=" + strings.TrimSpace(options.ConfigPath),
	}
	if strings.TrimSpace(pluginID) != "" {
		env = append(env, plugschema.EnvPluginID+"="+strings.TrimSpace(pluginID))
	}
	env = append(env, proxyEnv(options)...)
	cleanup := func() {}
	pluginConfig := options.PluginConfigs.ForPlugin(pluginID)
	if kind != "" {
		// The component kind disambiguates same-named components of different
		// kinds so a plugin never receives another component's configuration.
		pluginConfig = options.PluginConfigs.ForComponent(string(kind), pluginID)
	}
	if pluginConfig != nil {
		path, remove, err := writePluginConfigFile(pluginConfig)
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
