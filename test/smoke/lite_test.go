//go:build smoke

package smoke

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bomlyLiteBin is the path to the lite binary, built once per test run.
// It is set lazily by buildLiteBinary.
var bomlyLiteBin string

// buildLiteBinary builds the lite binary (no builtin Syft/Grype) once and
// caches the path. Safe to call from multiple tests — only the first call
// builds.
func buildLiteBinary(t *testing.T) string {
	t.Helper()
	if bomlyLiteBin != "" {
		return bomlyLiteBin
	}

	dir, err := os.MkdirTemp("", "bomly-lite-smoke-*")
	if err != nil {
		t.Fatalf("create temp dir for lite binary: %v", err)
	}
	binName := "bomly-lite"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	outPath := filepath.Join(dir, binName)

	repoRoot := repoRoot(t)
	build := exec.Command("go", "build", "-o", outPath, "./cmd/bomly")
	build.Dir = repoRoot

	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build bomly-lite: %v\n%s", err, string(out))
	}
	bomlyLiteBin = outPath
	return outPath
}

// runBomlyLite is like runBomly but uses the lite binary.
func runBomlyLite(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runBomlyLiteWithEnv(t, nil, args...)
}

// runBomlyLiteWithEnv is like runBomlyWithEnv but uses the lite binary.
func runBomlyLiteWithEnv(t *testing.T, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := buildLiteBinary(t)
	origBin := bomlyBin
	bomlyBin = bin
	defer func() { bomlyBin = origBin }()
	return runBomlyWithEnv(t, env, args...)
}

// ---------------------------------------------------------------------------
// Lite scan tests — native detectors work without builtin Syft/Grype.
// ---------------------------------------------------------------------------

func TestLiteScan(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "lite-scan-go",
			args:  []string{"scan", "--url", "https://github.com/google/uuid", "--ref", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
		{
			name: "lite-scan-sbom-spdx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.spdx.json"), "--format", "json"},
		},
		{
			name: "lite-scan-sbom-cyclonedx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.cdx.json"), "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomlyLite(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly-lite exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly-lite produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Lite diff test — native detectors work without builtin Syft/Grype.
// ---------------------------------------------------------------------------

func TestLiteDiff(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "lite-diff-go",
			args:  []string{"diff", "--url", "https://github.com/google/uuid", "--base", "v1.5.0", "--head", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomlyLite(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly-lite exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly-lite produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Lite explain test
// ---------------------------------------------------------------------------

func TestLiteExplain(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "lite-explain-go",
			args:  []string{"explain", "github.com/google/uuid", "--url", "https://github.com/google/uuid", "--ref", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomlyLite(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly-lite exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly-lite produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Lite version test — confirms the binary runs and reports no builtins.
// ---------------------------------------------------------------------------

func TestLiteVersion(t *testing.T) {
	stdout, stderr, code := runBomlyLite(t, "version")
	if code != 0 {
		t.Fatalf("bomly-lite version exited %d\nstderr:\n%s", code, stderr)
	}
	if len(stdout) == 0 {
		t.Fatal("bomly-lite version produced no output")
	}
	// The lite binary should NOT report embedded Grype — it is gated behind
	// the bomly_builtin_grype build tag which the lite build omits.
	if strings.Contains(stdout, "Grype (github.com/anchore/grype)") {
		t.Error("lite binary unexpectedly reports builtin Grype")
	}
}
