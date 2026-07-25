// Package ciready inspects the package-manager configuration around each
// resolved subproject and reports CI-readiness hints: mismatches and install
// policy gates that make a CI install fail even when every vulnerability has
// been fixed.
//
// The inspection is read-only and best-effort. It reads manifests, lockfiles,
// and package-manager config files, and queries the version of package-manager
// binaries already on PATH. It never installs anything, never contacts the
// network, and never fails the pipeline: unreadable or unrecognized inputs are
// skipped silently.
package ciready

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// toolVersionTimeout bounds a single `<manager> --version` probe. The command
// is local and near-instant; the timeout only guards a hung binary.
const toolVersionTimeout = 10 * time.Second

// Diagnostic is one CI-readiness hint. Source names the tool or config the hint
// is about (e.g. "pnpm"); Message is the human-readable explanation.
type Diagnostic struct {
	Source  string
	Message string
}

// ToolVersionFunc reports the version string printed by a package-manager
// binary on PATH. It returns ok=false when the binary is absent or its output
// cannot be parsed.
type ToolVersionFunc func(ctx context.Context, binary string) (version string, ok bool)

// Inspector runs the CI-readiness checks. The zero value is usable.
type Inspector struct {
	Logger *zap.Logger
	// ToolVersion overrides the PATH version probe. Tests inject a stub; the
	// zero value runs `<binary> --version`.
	ToolVersion ToolVersionFunc
}

// Inspect returns CI-readiness hints for the given subprojects. Duplicate hints
// (same source and message, e.g. a repo-root config shared by several
// subprojects) are reported once.
func (i Inspector) Inspect(ctx context.Context, subprojects []sdk.Subproject) []Diagnostic {
	r := &run{
		logger:      i.Logger,
		toolVersion: i.ToolVersion,
		versions:    make(map[string]probedVersion),
	}
	if r.logger == nil {
		r.logger = zap.NewNop()
	}
	if r.toolVersion == nil {
		r.toolVersion = commandVersion
	}

	var diagnostics []Diagnostic
	seen := make(map[string]struct{})
	for _, subproject := range subprojects {
		for _, diagnostic := range r.inspectSubproject(ctx, subproject) {
			key := diagnostic.Source + "\x00" + diagnostic.Message
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	return diagnostics
}

// run carries per-Inspect state: the version cache shared across subprojects so
// each package-manager binary is probed at most once per scan.
type run struct {
	logger      *zap.Logger
	toolVersion ToolVersionFunc
	versions    map[string]probedVersion
}

type probedVersion struct {
	version string
	ok      bool
}

func (r *run) inspectSubproject(ctx context.Context, subproject sdk.Subproject) []Diagnostic {
	if subproject.ExecutionTarget.Kind == sdk.ExecutionTargetContainerImage {
		return nil
	}
	dir := projectDir(subproject.ExecutionTarget.Location)
	if dir == "" {
		return nil
	}
	if !hasNodeManager(subproject.DetectedPackageManagers) {
		return nil
	}
	return r.inspectNodeProject(ctx, dir, subproject.RelativePath)
}

// projectDir normalizes an execution-target location to the directory the
// package-manager config lives in. File targets (a lockfile or manifest passed
// directly) resolve to their parent directory.
func projectDir(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	info, err := os.Stat(location)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return location
	}
	return filepath.Dir(location)
}

// version returns the version reported by binary, probing PATH at most once per
// binary per Inspect call.
func (r *run) version(ctx context.Context, binary string) (string, bool) {
	if cached, ok := r.versions[binary]; ok {
		return cached.version, cached.ok
	}
	version, ok := r.toolVersion(ctx, binary)
	r.versions[binary] = probedVersion{version: version, ok: ok}
	r.logger.Debug("ci-readiness: probed package manager version",
		zap.String("binary", binary),
		zap.String("version", version),
		zap.Bool("found", ok),
	)
	return version, ok
}

// commandVersion runs `<binary> --version` and returns the first version-like
// token in its output.
func commandVersion(ctx context.Context, binary string) (string, bool) {
	if _, err := system.LookPath(binary); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, toolVersionTimeout)
	defer cancel()
	cmd := system.CommandContext(ctx, binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return parseVersionOutput(string(out))
}

// parseVersionOutput extracts a version from `--version` output. Node prints
// "v22.3.0"; npm, pnpm, yarn, and bun print a bare semver.
func parseVersionOutput(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		for _, field := range strings.Fields(line) {
			candidate := strings.TrimPrefix(strings.TrimSpace(field), "v")
			if candidate == "" || !isDigit(candidate[0]) {
				continue
			}
			return candidate, true
		}
	}
	return "", false
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// pathPrefix labels a hint with the subproject it came from. The repository
// root is left unlabeled.
func pathPrefix(relativePath string) string {
	relativePath = strings.TrimSpace(relativePath)
	if relativePath == "" || relativePath == "." {
		return ""
	}
	return "subproject " + relativePath + ": "
}
