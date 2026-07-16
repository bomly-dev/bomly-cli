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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
)

// TestScanBunLockfile exercises the native text-lockfile path against a
// pinned public monorepo. The compact golden locks the detector identity,
// workspace partitioning, complete package inventory, and two known versions
// without committing a multi-thousand-line scan document.
func TestScanBunLockfile(t *testing.T) {
	stdout, stderr, code := runBomly(t,
		"scan", "--url", "https://github.com/cline/cline.git",
		"--ref", "d7cc9b61557aa0efd962512c16d183f49aa6bf20",
		"--detectors", "bun", "--format", "json")
	if code != 0 {
		t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
	}
	var document struct {
		Manifests []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"manifests"`
		Packages []struct {
			PURL    string `json:"purl"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decode Bun scan output: %v", err)
	}
	selected := make([]map[string]string, 0, 2)
	for _, pkg := range document.Packages {
		if pkg.Name == "esbuild" || pkg.Name == "vite" {
			selected = append(selected, map[string]string{"name": pkg.Name, "version": pkg.Version, "purl": pkg.PURL})
		}
	}
	projection := map[string]any{
		"manifest_count": len(document.Manifests),
		"package_count":  len(document.Packages),
		"root_manifest":  document.Manifests[0],
		"selected":       selected,
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("encode Bun smoke projection: %v", err)
	}
	assertGolden(t, "scan-bun", normalizeJSON(t, raw))
}

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

	targets, err := benchmark.LoadTargets("")
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
			// Reachability smoke pinned to bomly-dev/example-go-gomod. The
			// repo deliberately calls into golang.org/x/text v0.3.5's
			// language.Parse (GHSA-69ch-w2m2-3vjp / CVE-2022-32149) via
			// main → sub3.Baz, which the analyzer reports as reachable at
			// the symbol tier with a non-empty call_paths slice. go.sum
			// pins the graph. Goldens scrub volatile fields (call frame
			// line numbers, file paths, analyzed_at) via
			// normalizeReachability.
			name:  "scan-go-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--enrich", "--analyze", "--format", "json"},
			tools: []string{"go"},
		},
		{
			// jsreach smoke pinned to bomly-dev/example-javascript-npm, a
			// deliberately-vulnerable demo Node.js app. server.js calls
			// js-yaml.load directly (RCE) and transitively through the
			// `to` lib, and imports lodash/marked, while other deps are
			// unreachable from app code — so the smoke exercises both
			// "reachable (package)" and "unreachable (package)" branches
			// of the analyzer. package-lock.json pins the graph. Goldens
			// scrub timestamps via normalizeReachability.
			name:  "scan-npm-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--enrich", "--analyze", "--format", "json"},
			tools: []string{"npm"},
		},
		{
			// pyreach smoke pinned to bomly-dev/example-python-pip, a
			// deliberately-vulnerable demo. main.py imports
			// jwt / django / rsa / requests directly; the committed
			// requirements.lock pins the full transitive closure so the
			// detector resolves a stable graph via the requirements.lock
			// fast-path instead of inspecting the ambient environment.
			// Exercises the directly-imported, transitively-reachable
			// (urllib3, idna, chardet, certifi via requests; pyasn1 via
			// rsa; pytz via django), and unimported (feedparser, sgmllib3k,
			// jinja2, pyyaml, sqlalchemy) branches plus the
			// module-to-distribution override (jwt → pyjwt). Goldens scrub
			// timestamps via normalizeReachability.
			name:  "scan-python-pip-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-python-pip", "--ref", "fe04c758134b95dab102e1fce10275f7d18c0cf2", "--enrich", "--analyze", "--format", "json"},
			tools: []string{"pip"},
		},
		{
			// jvmreach smoke pinned to bomly-dev/example-java-maven, a
			// deliberately-vulnerable Maven demo. Main.java imports
			// Apache Commons FileUpload, Apache XMLSec, jBCrypt, and
			// Spring Web. Dependencies include Struts2, Keycloak,
			// H2, Kafka, OrientDB, JavaMelody, Sling — most of which
			// are unimported from app source but reachable through
			// dep edges. Maven resolves the pinned pom deterministically.
			// Exercises directly-imported, transitively-reachable, and
			// unreachable branches plus the package-prefix map. Goldens
			// scrub timestamps via normalizeReachability.
			name:  "scan-java-maven-reachability",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-java-maven", "--ref", "v1.0.0", "--enrich", "--analyze", "--format", "json"},
			tools: []string{"mvn"},
		},
		{
			// Scope smoke pinned to bomly-dev/example-javascript-npm. With
			// --scope runtime the dev dependency (mocha) is excluded, so the
			// golden proves runtime-only filtering. package-lock.json pins
			// the graph.
			name:  "scan-npm-scope-runtime",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--format", "json", "--scope", "runtime"},
			tools: []string{"npm"},
		},
		{
			// Recursive discovery smoke pinned to bomly-dev/bomly-agent-study
			// (tag v1-fixtures-final). The repo has no manifest at its root and
			// independent projects in nested directories; the golden proves
			// nested subprojects resolve with repo-relative manifest paths and
			// distinct subproject values across two ecosystems:
			// fixtures/api-java (Maven, native TGF) and fixtures/webapp (npm,
			// lockfile parser). The pip projects (fixtures/service, harness/)
			// are excluded because their graphs resolve through a live
			// `pip install` (no committed requirements.lock fast-path), which
			// is not deterministic across environments; the exclusions also
			// exercise --exclude. Same-named-manifest dedup across nested
			// subprojects is covered by consolidation unit tests.
			name:  "scan-recursive-monorepo",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/bomly-agent-study", "--ref", "fc32147b3be526ea6c5d563a505c867f4bae93f3", "--recursive", "--exclude", "harness,fixtures/service", "--format", "json"},
			tools: []string{"mvn"},
		},
		{
			// npm workspaces pinned to bomly-dev/example-javascript-npm-workspaces:
			// a root dependency plus two members sharing pinned vulnerable
			// deps, a workspace link (web -> lib), and a member devDependency.
			// The golden proves one manifest entry per workspace member
			// (apps/web/package.json, packages/lib/package.json) alongside the
			// root lockfile entry. Lockfile parsing needs no npm binary.
			name: "scan-npm-workspaces",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm-workspaces", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			// pnpm workspace pinned to bomly-dev/example-javascript-pnpm-workspaces
			// (same shape as the npm fixture, resolved through pnpm-lock.yaml
			// importers). Lockfile parsing needs no pnpm binary.
			name: "scan-pnpm-workspaces",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-pnpm-workspaces", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			// Virtual Cargo workspace pinned to bomly-dev/example-rust-cargo-workspace:
			// a workspace-only root Cargo.toml (no [package]) with two members,
			// one depending on the other. The golden proves per-member entries
			// from the Cargo.lock partitioning path (no cargo binary needed)
			// and that virtual roots resolve natively instead of erroring.
			name: "scan-cargo-workspace",
			args: []string{"scan", "--url", "https://github.com/bomly-dev/example-rust-cargo-workspace", "--ref", "v1.0.0", "--format", "json"},
		},
		{
			// Maven reactor pinned to bomly-dev/example-java-maven-multimodule:
			// a pom-packaging parent with two modules, web depending on the
			// core module. The golden proves one manifest entry per reactor
			// module (core/pom.xml, web/pom.xml) plus the parent root entry.
			name:  "scan-maven-multimodule",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-java-maven-multimodule", "--ref", "v1.0.0", "--format", "json"},
			tools: []string{"mvn"},
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
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
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

// TestScanRecursiveNothingAtRootWithoutFlag locks in the non-recursive
// default: scanning the pinned monorepo (which has no root manifest) without
// --recursive must exit 5 (nothing to evaluate) and point the user at
// --recursive via the discovery-probe hint.
func TestScanRecursiveNothingAtRootWithoutFlag(t *testing.T) {
	t.Parallel()
	_, stderr, code := runBomly(t,
		"scan",
		"--url", "https://github.com/bomly-dev/bomly-agent-study",
		"--ref", "fc32147b3be526ea6c5d563a505c867f4bae93f3",
		"--format", "json",
	)
	if code != 5 {
		t.Fatalf("expected exit 5 for a rootless monorepo without --recursive, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "retry with --recursive") {
		t.Fatalf("expected --recursive hint in stderr, got:\n%s", stderr)
	}
}

// TestScanRecursiveDepthLimitFindsNothing exercises the depth bound end to
// end: at --max-depth 1 the pinned monorepo's nested projects (all at depth 2)
// are out of reach and the only depth-1 candidate (harness) is excluded, so
// the scan must exit 5 and describe the bounded recursive search. The
// scan-recursive-monorepo golden already covers the implicit default depth
// finding nested projects.
func TestScanRecursiveDepthLimitFindsNothing(t *testing.T) {
	t.Parallel()
	_, stderr, code := runBomly(t,
		"scan",
		"--url", "https://github.com/bomly-dev/bomly-agent-study",
		"--ref", "fc32147b3be526ea6c5d563a505c867f4bae93f3",
		"--recursive",
		"--max-depth", "1",
		"--exclude", "harness",
		"--format", "json",
	)
	if code != 5 {
		t.Fatalf("expected exit 5 when the depth limit hides every manifest, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "recursive discovery, max depth 1, 1 exclude pattern(s)") {
		t.Fatalf("expected bounded recursive-search description in stderr, got:\n%s", stderr)
	}
	if strings.Contains(stderr, "retry with --recursive") {
		t.Fatalf("recursive run must not suggest --recursive, got:\n%s", stderr)
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
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
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
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
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
