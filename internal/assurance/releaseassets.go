package assurance

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// maxAssetBytes bounds one release asset read during verification.
const maxAssetBytes = 512 << 20

// maxExtractedBytes bounds one file extracted from a release archive.
const maxExtractedBytes = 512 << 20

// releasePlatforms are the operating system and architecture pairs every
// release ships binaries for.
var releasePlatforms = []struct{ OS, Arch string }{
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"linux", "amd64"}, {"linux", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

// linuxPackageFormats are the Linux package file extensions a release ships.
var linuxPackageFormats = []string{"apk", "deb", "pkg.tar.zst", "rpm"}

// ArchiveName returns the release archive file name for one binary, version,
// and platform. version is the tag without its leading "v".
func ArchiveName(binary, version, goos, goarch string) string {
	extension := "tar.gz"
	if goos == "windows" {
		extension = "zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s.%s", binary, version, goos, goarch, extension)
}

// ExpectedAssets lists every file a published release must carry, sorted.
// version is the release tag without its leading "v".
func ExpectedAssets(version string) []string {
	assets := []string{"SHA256SUMS", "SHA256SUMS.sigstore.json", "multiple.intoto.jsonl"}
	for _, platform := range releasePlatforms {
		assets = append(assets,
			ArchiveName("bomly", version, platform.OS, platform.Arch),
			ArchiveName("bomly-lite", version, platform.OS, platform.Arch),
		)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, format := range linuxPackageFormats {
			assets = append(assets, fmt.Sprintf("bomly_%s_linux_%s.%s", version, arch, format))
		}
	}
	sort.Strings(assets)
	return assets
}

// ChecksumEntries maps asset file names to their recorded SHA-256 hashes.
type ChecksumEntries map[string]string

// ParseSHA256SUMS reads a GoReleaser SHA256SUMS document.
func ParseSHA256SUMS(data []byte) (ChecksumEntries, error) {
	entries := ChecksumEntries{}
	for index, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			return nil, fmt.Errorf("SHA256SUMS line %d is malformed", index+1)
		}
		hash := fields[0]
		name := strings.TrimPrefix(fields[1], "*")
		if !hashPattern.MatchString(hash) {
			return nil, fmt.Errorf("SHA256SUMS line %d has an invalid hash", index+1)
		}
		if name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("SHA256SUMS line %d has an invalid file name", index+1)
		}
		entries[name] = hash
	}
	if len(entries) == 0 {
		return nil, errCatalog("SHA256SUMS lists no files")
	}
	return entries, nil
}

// AssetPresence reports which expected assets a directory holds.
type AssetPresence struct {
	Present []string
	Missing []string
	Extra   []string
}

// InspectAssets compares the files in dir against the expected asset list.
func InspectAssets(dir, version string) (AssetPresence, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return AssetPresence{}, fmt.Errorf("read release asset directory: %w", err)
	}
	found := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		found[entry.Name()] = struct{}{}
	}
	presence := AssetPresence{}
	expected := map[string]struct{}{}
	for _, name := range ExpectedAssets(version) {
		expected[name] = struct{}{}
		if _, ok := found[name]; ok {
			presence.Present = append(presence.Present, name)
			continue
		}
		presence.Missing = append(presence.Missing, name)
	}
	for name := range found {
		if _, ok := expected[name]; !ok {
			presence.Extra = append(presence.Extra, name)
		}
	}
	sort.Strings(presence.Extra)
	return presence, nil
}

// ChecksumOutcome is the result of hashing the assets present in a directory.
type ChecksumOutcome struct {
	Verified   []string
	Mismatched []string
	Unlisted   []string
	// NotDownloaded names files SHA256SUMS lists that are absent locally, which
	// is expected when only the platform-native assets were fetched.
	NotDownloaded []string
}

// VerifyChecksums hashes every file in dir and compares it to SHA256SUMS.
func VerifyChecksums(dir string, entries ChecksumEntries) (ChecksumOutcome, error) {
	outcome := ChecksumOutcome{}
	present := map[string]struct{}{}
	files, err := os.ReadDir(dir)
	if err != nil {
		return outcome, fmt.Errorf("read release asset directory: %w", err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if name == "SHA256SUMS" || name == "SHA256SUMS.sigstore.json" || name == "multiple.intoto.jsonl" {
			continue
		}
		present[name] = struct{}{}
		want, listed := entries[name]
		if !listed {
			outcome.Unlisted = append(outcome.Unlisted, name)
			continue
		}
		actual, hashErr := hashFile(filepath.Join(dir, name))
		if hashErr != nil {
			return outcome, hashErr
		}
		if actual != want {
			outcome.Mismatched = append(outcome.Mismatched, name)
			continue
		}
		outcome.Verified = append(outcome.Verified, name)
	}
	for name := range entries {
		if _, ok := present[name]; !ok {
			outcome.NotDownloaded = append(outcome.NotDownloaded, name)
		}
	}
	sort.Strings(outcome.Verified)
	sort.Strings(outcome.Mismatched)
	sort.Strings(outcome.Unlisted)
	sort.Strings(outcome.NotDownloaded)
	return outcome, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxAssetBytes)); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// BinaryProbe is the outcome of extracting one release archive and asking the
// binary inside it for its version.
type BinaryProbe struct {
	Archive string
	Binary  string
	Output  string
	Status  Status
	Note    string
}

// ProbeNativeBinaries extracts the archives built for the host platform and
// checks that each binary reports the released version.
func ProbeNativeBinaries(ctx context.Context, dir, version, workDir string) ([]BinaryProbe, error) {
	var probes []BinaryProbe
	for _, binary := range []string{"bomly", "bomly-lite"} {
		archive := ArchiveName(binary, version, runtime.GOOS, runtime.GOARCH)
		probe := BinaryProbe{Archive: archive, Binary: binary, Status: StatusFail}
		target := filepath.Join(workDir, binary)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return nil, fmt.Errorf("create extraction directory: %w", err)
		}
		executable, err := extractBinary(filepath.Join(dir, archive), target, binary)
		if err != nil {
			probe.Note = err.Error()
			probes = append(probes, probe)
			continue
		}
		output, err := runVersion(ctx, executable)
		probe.Output = output
		switch {
		case err != nil:
			probe.Note = err.Error()
		case !strings.Contains(output, version):
			probe.Note = fmt.Sprintf("reported %q, want version %s", output, version)
		default:
			probe.Status = StatusPass
		}
		probes = append(probes, probe)
	}
	return probes, nil
}

func runVersion(ctx context.Context, executable string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(runCtx, executable, "version")
	output, err := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return text, fmt.Errorf("run %s version: %w", filepath.Base(executable), err)
	}
	return text, nil
}

// extractBinary pulls one named binary out of a release archive into target.
func extractBinary(archivePath, target, binary string) (string, error) {
	name := binary
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, target, name)
	}
	return extractFromTarGz(archivePath, target, name)
}

func extractFromZip(archivePath, target, name string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", filepath.Base(archivePath), err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		if filepath.Base(file.Name) != name || file.FileInfo().IsDir() {
			continue
		}
		source, openErr := file.Open()
		if openErr != nil {
			return "", fmt.Errorf("read %s from %s: %w", name, filepath.Base(archivePath), openErr)
		}
		defer source.Close()
		return writeExecutable(filepath.Join(target, name), source)
	}
	return "", fmt.Errorf("%s does not contain %s", filepath.Base(archivePath), name)
}

func extractFromTarGz(archivePath, target, name string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", filepath.Base(archivePath), err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Base(archivePath), err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, readErr := tarReader.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("read %s: %w", filepath.Base(archivePath), readErr)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != name {
			continue
		}
		return writeExecutable(filepath.Join(target, name), tarReader)
	}
	return "", fmt.Errorf("%s does not contain %s", filepath.Base(archivePath), name)
}

// writeExecutable copies a bounded amount of archive content to an executable
// file. Destinations are always names this package chose, never archive paths,
// so an archive cannot direct a write outside the extraction directory.
func writeExecutable(destination string, source io.Reader) (string, error) {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Base(destination), err)
	}
	written, copyErr := io.Copy(file, io.LimitReader(source, maxExtractedBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", fmt.Errorf("write %s: %w", filepath.Base(destination), copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", filepath.Base(destination), closeErr)
	}
	if written > maxExtractedBytes {
		return "", fmt.Errorf("%s exceeds the %d byte extraction limit", filepath.Base(destination), maxExtractedBytes)
	}
	return destination, nil
}
