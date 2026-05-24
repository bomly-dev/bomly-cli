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

	"github.com/bomly-dev/bomly-cli/test/qa"
)

// bomlyBin is the path to the compiled CLI binary, built once in TestMain.
var bomlyBin string
var smokeRuntimeDir string
var smokeGOPATH string
var smokeGOMODCACHE string
var smokeGOCACHE string

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

	smokeRuntimeDir, err = os.MkdirTemp("", "bomly-smoke-runtime-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: create runtime dir: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	smokeGOPATH = filepath.Join(smokeRuntimeDir, "gopath")
	smokeGOMODCACHE = filepath.Join(smokeGOPATH, "pkg", "mod")
	smokeGOCACHE = filepath.Join(smokeRuntimeDir, "gocache")
	for _, path := range []string{smokeGOPATH, smokeGOMODCACHE, smokeGOCACHE} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "smoke: create runtime path %s: %v\n", path, err)
			_ = os.RemoveAll(dir)
			_ = os.RemoveAll(smokeRuntimeDir)
			os.Exit(1)
		}
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	_ = os.RemoveAll(smokeRuntimeDir)
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
		tools []string // required tools - skip if any missing
	}{}

	targets, err := qa.LoadScanTargets(qa.DefaultTargetsPath(repoRoot(t)))
	if err != nil {
		t.Fatalf("load shared scan targets: %v", err)
	}
	for _, target := range targets {
		cases = append(cases, struct {
			name  string
			args  []string
			tools []string
		}{
			name:  target.Name,
			args:  target.SmokeArgs(),
			tools: target.Tools,
		})
	}
	cases = append(cases, []struct {
		name  string
		args  []string
		tools []string // required tools - skip if any missing
	}{
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
			// jsreach smoke pinned to snyk-labs/nodejs-goof, a real
			// vulnerable demo Node.js todo app. The project's app.js
			// imports a meaningful subset of its npm dependencies
			// directly (mongoose, lodash, express-fileupload, etc.)
			// while many transitive ones are unreachable from app
			// code, so the smoke exercises both "reachable (package)"
			// and "unreachable (package)" branches of the analyzer.
			// Goldens scrub timestamps via normalizeReachability.
			name:  "scan-npm-reachability",
			args:  []string{"scan", "--url", "https://github.com/snyk-labs/nodejs-goof", "--ref", "add14ba59e98240d9e00a235dd7d42cd61ae9912", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			// pyreach smoke pinned to veracode/example-python3-pip,
			// a deliberately-vulnerable demo. main.py imports
			// jwt / django / rsa / requests directly; requirements.txt
			// pins ten more deps that are either unimported (feedparser,
			// sgmllib3k) or reachable only transitively (urllib3, idna,
			// chardet, certifi, pyasn1, pytz). Exercises the
			// directly-imported, transitively-reachable, and
			// unreachable branches plus the module-to-distribution
			// override (jwt → pyjwt). Goldens scrub timestamps via
			// normalizeReachability.
			name:  "scan-python-pip-reachability",
			args:  []string{"scan", "--url", "https://github.com/veracode/example-python3-pip", "--ref", "e19d10938caf3e06730c23047ae118cd59638e41", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			// jvmreach smoke pinned to veracode/example-java-maven, a
			// deliberately-vulnerable Maven demo. Main.java imports
			// Apache Commons FileUpload, Apache XMLSec, jBCrypt, and
			// Spring Web. requirements include Struts2, Keycloak,
			// H2, Kafka, OrientDB, JavaMelody, Sling — most of which
			// are unimported from app source but reachable through
			// dep edges. Exercises directly-imported, transitively-
			// reachable, and unreachable branches plus the
			// package-prefix map. Goldens scrub timestamps via
			// normalizeReachability.
			name:  "scan-java-maven-reachability",
			args:  []string{"scan", "--url", "https://github.com/veracode/example-java-maven", "--ref", "509948ba5a02ffab48e7260031d4a1e78d010891", "--enrich", "--reachability", "--format", "json"},
			tools: []string{"mvn"},
		},
		{
			name:  "scan-npm-scope-runtime",
			args:  []string{"scan", "--url", "https://github.com/ljharb/qs", "--ref", "v6.13.0", "--format", "json", "--scope", "runtime"},
			tools: []string{"npm"},
		},
		{
			// Grant license enrichment smoke pinned to sirupsen/logrus v1.9.3,
			// a small Go module with a permissive license graph. Negative
			// matcher selectors isolate Grant from the other license sources
			// (deps.dev, ClearlyDefined) so any pkg.Licenses with
			// Type="external-grant" in the output came from this matcher.
			// Requires the grant CLI on PATH; skips otherwise.
			name:  "scan-go-grant-license-enrichment",
			args:  []string{"scan", "--url", "https://github.com/sirupsen/logrus", "--ref", "v1.9.3", "--enrich", "--matchers", "+grant-license-checker,-clearlydefined-license-checker,-depsdev-license-checker", "--format", "json"},
			tools: []string{"go", "grant"},
		},
		{
			name: "scan-sbom-spdx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.spdx.json"), "--format", "json"},
		},
		{
			name: "scan-sbom-cyclonedx",
			args: []string{"scan", "--sbom", "--path", sbomFixture("go.cdx.json"), "--format", "json"},
		},
	}...)

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
