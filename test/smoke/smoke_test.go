//go:build smoke

// Package smoke provides end-to-end smoke tests for the Bomly CLI.
// These tests build the real binary, execute it as a subprocess against
// pinned public repositories and container images, and compare JSON output
// against recorded golden files.
//
// Run:
//
//	make smoke                 # normal run — compare against golden files
//	make smoke ARGS="-update"  # regenerate golden files
package smoke

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// bomlyBin is the path to the compiled CLI binary, built once in TestMain.
var bomlyBin string

func TestMain(m *testing.M) {
	// Ensure git is available — all URL-based tests need it.
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "smoke: git not found on PATH — skipping all tests")
		os.Exit(0)
	}

	dir, err := os.MkdirTemp("", "bomly-smoke-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: create temp dir: %v\n", err)
		os.Exit(1)
	}

	binName := "bomly"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bomlyBin = filepath.Join(dir, binName)

	// Build the default binary, which includes builtin Syft/Grype support.
	// The working directory must be the repo root so the module is resolved.
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: find repo root: %v\n", err)
		os.Exit(1)
	}

	build := exec.Command("go", "build", "-o", bomlyBin, "./cmd/bomly")
	build.Dir = repoRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr

	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "smoke: build bomly binary: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// findRepoRoot locates the repo root from the test directory (test/smoke/).
func findRepoRoot() (string, error) {
	here, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(here, "..", ".."))
}

// ---------------------------------------------------------------------------
// Scan tests
// ---------------------------------------------------------------------------

func TestScan(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string // required tools — skip if any missing
	}{
		{
			name:  "scan-go",
			args:  []string{"scan", "--url", "https://github.com/google/uuid", "--ref", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
		{
			// Reachability smoke pinned to veracode/example-go-modules
			// at the "Adding a known vulnerable method" commit. The
			// repo deliberately calls into golang.org/x/text v0.3.5's
			// language.Parse (GHSA-69ch-w2m2-3vjp / CVE-2022-32149),
			// which the analyzer reports as reachable at the symbol
			// tier with a non-empty call_paths slice. Goldens scrub
			// volatile fields (call frame line numbers, file paths,
			// analyzed_at) via normalizeReachability.
			name:  "scan-go-reachability",
			args:  []string{"scan", "--url", "https://github.com/veracode/example-go-modules", "--ref", "555ebe70813318ce80f46e3c4fc6623012e0317d", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"go"},
		},
		{
			name:  "scan-npm",
			args:  []string{"scan", "--url", "https://github.com/ljharb/qs", "--ref", "v6.13.0", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name:  "scan-maven",
			args:  []string{"scan", "--url", "https://github.com/google/gson", "--ref", "gson-parent-2.11.0", "--format", "json"},
			tools: []string{"mvn"},
		},
		{
			name:  "scan-python-pip",
			args:  []string{"scan", "--url", "https://github.com/psf/requests", "--ref", "v2.32.3", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			name: "scan-composer",
			args: []string{"scan", "--url", "https://github.com/guzzle/guzzle", "--ref", "7.9.2", "--format", "json"},
			//tools: []string{"composer"},
		},
		{
			name: "scan-bundler",
			args: []string{"scan", "--url", "https://github.com/rack/rack", "--ref", "v3.1.8", "--format", "json"},
			//tools: []string{"bundle"},
		},
		{
			name: "scan-github-actions",
			args: []string{"scan", "--url", "https://github.com/actions/checkout", "--ref", "v4.2.2", "--format", "json", "--ecosystems", "github-actions"},
		},
		{
			name: "scan-nuget",
			args: []string{"scan", "--url", "https://github.com/pi-apps/SilkRoad", "--ref", "8c273f35c4a021ba73482f06636e730dd24b080d", "--format", "json", "--ecosystems", "dotnet"},
		},
		{
			name: "scan-cargo",
			args: []string{"scan", "--url", "https://github.com/BurntSushi/ripgrep", "--ref", "4519153e5e461527f4bca45b042fff45c4ec6fb9", "--format", "json", "--ecosystems", "rust"},
		},
		{
			name: "scan-pub",
			args: []string{"scan", "--url", "https://github.com/KhoaSuperman/findseat", "--ref", "53007f252ec7143718e3f273a802e26b67cf2739", "--format", "json", "--ecosystems", "dart"},
		},
		{
			name: "scan-cocoapods",
			args: []string{"scan", "--url", "https://github.com/material-motion/motion-interchange-objc", "--ref", "835474053336d2004c079f7d6580f582a7a2b85a", "--format", "json", "--ecosystems", "swift"},
		},
		{
			name: "scan-mix",
			args: []string{"scan", "--url", "https://github.com/phoenixframework/phoenix", "--ref", "05e0b5b26a65124e768e0ab55b86bba30a531e14", "--format", "json", "--ecosystems", "elixir"},
		},
		{
			name: "scan-swiftpm",
			args: []string{"scan", "--url", "https://github.com/vapor/vapor", "--ref", "ebbe71c89aa1b76a0920277760b12be7a2ec7c70", "--format", "json", "--ecosystems", "swift"},
		},
		{
			name: "scan-sbt",
			args: []string{"scan", "--url", "https://github.com/ucb-bar/chiseltest", "--ref", "8315873827715841f75af9b2d73e49214a1373d6", "--format", "json", "--ecosystems", "scala"},
		},
		{
			name:  "scan-npm-scope-runtime",
			args:  []string{"scan", "--url", "https://github.com/ljharb/qs", "--ref", "v6.13.0", "--format", "json", "--scope", "runtime"},
			tools: []string{"npm"},
		},
		{
			name: "scan-sbom-spdx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.spdx.json"), "--format", "json"},
		},
		{
			name: "scan-sbom-cyclonedx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.cdx.json"), "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Diff tests
// ---------------------------------------------------------------------------

func TestDiff(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "diff-go",
			args:  []string{"diff", "--url", "https://github.com/google/uuid", "--base", "v1.5.0", "--head", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
		{
			name:  "diff-npm",
			args:  []string{"diff", "--url", "https://github.com/ljharb/qs", "--base", "v6.12.0", "--head", "v6.13.0", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name: "diff-sbom",
			args: []string{"diff", "--sbom", "--base", sbomFixture("go.spdx.json"), "--head", sbomFixture("js.spdx.json"), "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Explain tests
// ---------------------------------------------------------------------------

func TestExplain(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "explain-go",
			args:  []string{"explain", "github.com/google/uuid", "--url", "https://github.com/google/uuid", "--ref", "v1.6.0", "--format", "json"},
			tools: []string{"go"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sbomFixture returns the absolute path to an SBOM fixture in testdata/sboms/.
func sbomFixture(name string) string {
	here, _ := os.Getwd()
	return filepath.Join(here, "testdata", "sboms", name)
}
