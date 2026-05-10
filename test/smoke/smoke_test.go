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
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"go"},
		},
		{
			// Reachability smoke: example-go-gomod v1.0.0 calls into
			// golang.org/x/text v0.3.5 (GHSA-69ch-w2m2-3vjp /
			// CVE-2022-32149) via language.Parse in sub3/sub3.go.
			// Goldens scrub volatile fields (call frame line numbers,
			// file paths, analyzed_at) via normalizeReachability.
			name:  "scan-go-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"go"},
		},
		{
			// jsreach smoke: example-javascript-npm v1.0.0 imports lodash
			// and marked directly (reachable), while many transitive deps
			// are unreachable from app code. Exercises both "reachable"
			// and "unreachable" branches of the analyzer.
			// Goldens scrub timestamps via normalizeReachability.
			name:  "scan-npm-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name:  "scan-npm",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name:  "scan-maven",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-java-maven", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"mvn"},
		},
		{
			name:  "scan-python-pip",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-pip", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			// pyreach smoke: example-python-pip v1.0.0 imports
			// jwt / django / rsa / requests directly; requirements.txt
			// pins more deps that are either unimported or transitively
			// reachable. Exercises directly-imported, transitively-reachable,
			// and unreachable branches plus the module-to-distribution
			// override (jwt → pyjwt). Goldens scrub timestamps via
			// normalizeReachability.
			name:  "scan-python-pip-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-pip", "--ref", "v1.0.0", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			name: "scan-composer",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-php-composer", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			name: "scan-bundler",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-ruby-bundler", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			name: "scan-github-actions",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-github-actions", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "github-actions"},
		},
		{
			name: "scan-nuget",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-dotnet-nuget", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "dotnet"},
		},
		{
			name: "scan-cargo",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-rust-cargo", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "rust"},
		},
		{
			name: "scan-pub",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-dart-pub", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "dart"},
		},
		{
			name: "scan-cocoapods",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-swift-cocoapods", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "swift"},
		},
		{
			name: "scan-mix",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-elixir-mix", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "elixir"},
		},
		{
			name: "scan-swiftpm",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-swift-swiftpm", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "swift"},
		},
		{
			name: "scan-sbt",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-scala-sbt", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "scala"},
		},
		{
			name:  "scan-yarn",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-yarn", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name:  "scan-pnpm",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-pnpm", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			name: "scan-gradle",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-java-gradle", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			name:  "scan-python-pipenv",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-pipenv", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			name:  "scan-python-poetry",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-poetry", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			name:  "scan-python-uv",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-uv", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"uv"},
		},
		{
			name: "scan-cpp-conan",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-cpp-conan", "--ref", "v1.0.0", "--format", "json", "--ecosystems", "cpp"},
		},
		{
			name:  "scan-npm-scope-runtime",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--format", "json", "--scope", "runtime"},
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
			args:  []string{"diff", "--url", "https://github.com/bomly-dev/example-go-gomod", "--base", "v0.9.0", "--head", "v1.0.0", "--format", "json"},
			tools: []string{"go"},
		},
		{
			name:  "diff-npm",
			args:  []string{"diff", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--base", "v0.9.0", "--head", "v1.0.0", "--format", "json"},
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
			args:  []string{"explain", "golang.org/x/text", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--ecosystems", "go", "--format", "json"},
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
