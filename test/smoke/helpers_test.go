//go:build smoke

package smoke

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

// runBomly executes the built CLI binary with the given arguments and returns
// stdout, stderr, and exit code. It does not fail the test on non-zero exit.
func runBomly(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runBomlyWithEnv(t, nil, args...)
}

// runBomlyWithEnv executes the built CLI binary with extra environment variables.
// Each element of env should be "KEY=VALUE". The current process environment is
// inherited and env entries are appended (overriding duplicates).
func runBomlyWithEnv(t *testing.T, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(bomlyBin, args...)
	cmd.Env = append(os.Environ(), env...)

	// Isolate plugin/config discovery to a throwaway home directory so the
	// host user's ~/.bomly does not leak into test runs.
	tempHome := t.TempDir()
	cmd.Env = append(cmd.Env, "HOME="+tempHome)
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "USERPROFILE="+tempHome)
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec bomly: %v", err)
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// normalizeJSON parses raw JSON, zeroes volatile fields that change between
// runs (durations, absolute paths), and re-marshals with sorted keys and
// consistent indentation.
func normalizeJSON(t *testing.T, raw []byte) []byte {
	t.Helper()

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("normalizeJSON: unmarshal: %v\nraw:\n%s", err, string(raw))
	}

	// Zero out top-level metadata.duration_ms.
	if md, ok := obj["metadata"].(map[string]any); ok {
		md["duration_ms"] = 0
	}

	// Normalize project.path and project.name — replace with fixed placeholders.
	// project.name is often derived from the temp clone directory name.
	if proj, ok := obj["project"].(map[string]any); ok {
		if _, hasPath := proj["path"]; hasPath {
			proj["path"] = "<normalized>"
		}
		if _, hasName := proj["name"]; hasName {
			proj["name"] = "<normalized>"
		}
	}

	// Normalize targets[*].project.path and targets[*].project.name (explain response).
	if targets, ok := obj["targets"].([]any); ok {
		for _, t := range targets {
			if tm, ok := t.(map[string]any); ok {
				if proj, ok := tm["project"].(map[string]any); ok {
					if _, hasPath := proj["path"]; hasPath {
						proj["path"] = "<normalized>"
					}
					if _, hasName := proj["name"]; hasName {
						proj["name"] = "<normalized>"
					}
				}
			}
		}
	}

	// Normalize results.manifests[*].path and .subproject for diff responses.
	if results, ok := obj["results"].(map[string]any); ok {
		if manifests, ok := results["manifests"].([]any); ok {
			for _, m := range manifests {
				normalizeManifestPaths(m)
			}
		}
	}

	// Normalize diff comparison paths so the same golden works across local
	// Windows development and Linux GitHub runners.
	if comparison, ok := obj["comparison"].(map[string]any); ok {
		normalizeComparisonPath(comparison, "base")
		normalizeComparisonPath(comparison, "head")
	}

	// Normalize manifests[*].path and .subproject for scan responses.
	if manifests, ok := obj["manifests"].([]any); ok {
		for _, m := range manifests {
			normalizeManifestPaths(m)
		}
	}

	// Scrub volatile reachability fields (analyzer timestamps, file paths
	// under temp clone dirs, line/column numbers that drift with upstream
	// source) so the same golden file is stable across runs.
	normalizeReachability(obj)

	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatalf("normalizeJSON: marshal: %v", err)
	}
	return append(out, '\n')
}

// normalizeReachability walks the JSON tree and scrubs volatile fields
// emitted by reachability analyzers (analyzed_at timestamps, frame
// file/line/column positions). The walker is depth-first and tolerant of
// shape variations between scan, diff, and explain responses; it looks
// for any map containing reachability or analyzer_stats keys, plus
// nested call_paths frames.
func normalizeReachability(node any) {
	switch v := node.(type) {
	case map[string]any:
		if r, ok := v["reachability"].(map[string]any); ok {
			scrubReachabilityFields(r)
		}
		if r, ok := v["analyzed_at"].(string); ok && r != "" {
			v["analyzed_at"] = "<timestamp>"
		}
		for _, child := range v {
			normalizeReachability(child)
		}
	case []any:
		for _, child := range v {
			normalizeReachability(child)
		}
	}
}

// scrubReachabilityFields zeroes the volatile fields on a reachability
// map: analyzed_at, every call_paths[*].frames[*].position file/line/column,
// and any frame.position with absolute file paths.
func scrubReachabilityFields(r map[string]any) {
	if _, ok := r["analyzed_at"]; ok {
		r["analyzed_at"] = "<timestamp>"
	}
	paths, ok := r["call_paths"].([]any)
	if !ok {
		return
	}
	for _, p := range paths {
		path, ok := p.(map[string]any)
		if !ok {
			continue
		}
		frames, ok := path["frames"].([]any)
		if !ok {
			continue
		}
		for _, f := range frames {
			frame, ok := f.(map[string]any)
			if !ok {
				continue
			}
			pos, ok := frame["position"].(map[string]any)
			if !ok {
				continue
			}
			if file, ok := pos["file"].(string); ok && file != "" {
				if filepath.IsAbs(file) {
					pos["file"] = "<repo>/" + filepath.Base(file)
				}
			}
			pos["line"] = 0
			pos["column"] = 0
			if _, ok := pos["end_line"]; ok {
				pos["end_line"] = 0
			}
		}
	}
}

// normalizeManifestPaths normalizes path and subproject within a manifest map.
func normalizeManifestPaths(m any) {
	mm, ok := m.(map[string]any)
	if !ok {
		return
	}
	// Manifest paths are typically relative already; only normalize absolute
	// paths or temp-dir prefixes.
	if p, ok := mm["path"].(string); ok && filepath.IsAbs(p) {
		mm["path"] = filepath.Base(p)
	}
	if s, ok := mm["subproject"].(string); ok && filepath.IsAbs(s) {
		mm["subproject"] = filepath.Base(s)
	}
}

// normalizeComparisonPath normalizes a comparison path field when it refers to
// a filesystem path. Named references like container tags are left unchanged.
func normalizeComparisonPath(m map[string]any, key string) {
	value, ok := m[key].(string)
	if !ok || !filepath.IsAbs(value) {
		return
	}
	m[key] = filepath.Base(value)
}

// goldenPath returns the full path to a golden file given a test case name.
func goldenPath(name string) string {
	return filepath.Join("testdata", "golden", name+".golden.json")
}

// assertGolden compares got (already normalized) against the golden file for
// name. When -update is passed, the golden file is written instead of compared.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	gp := goldenPath(name)

	if *update {
		if err := os.MkdirAll(filepath.Dir(gp), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(gp, got, 0o644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		t.Logf("updated golden file %s", gp)
		return
	}

	want, err := os.ReadFile(gp)
	if err != nil {
		t.Fatalf("read golden file %s: %v\nRun with -update to create it.", gp, err)
	}

	got = normalizeLineEndings(got)
	want = normalizeLineEndings(want)
	want = normalizeJSON(t, want)

	if !bytes.Equal(got, want) {
		t.Errorf("output does not match golden file %s\n\n--- want ---\n%s\n--- got ---\n%s\n\n--- diff (first divergence) ---\n%s",
			gp, string(want), string(got), firstDiff(want, got))
	}
}

func normalizeLineEndings(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// firstDiff returns a human-readable description of where two byte slices
// first diverge, showing a few lines of context.
func firstDiff(a, b []byte) string {
	linesA := strings.Split(string(a), "\n")
	linesB := strings.Split(string(b), "\n")

	max := len(linesA)
	if len(linesB) > max {
		max = len(linesB)
	}

	for i := 0; i < max; i++ {
		la, lb := "", ""
		if i < len(linesA) {
			la = linesA[i]
		}
		if i < len(linesB) {
			lb = linesB[i]
		}
		if la != lb {
			return fmt.Sprintf("line %d:\n  want: %s\n  got:  %s", i+1, la, lb)
		}
	}
	return "(no difference found)"
}

// requireTool skips the test if the named binary is not on PATH.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("required tool %q not found on PATH", name)
	}
}

// requireGit skips the test if git is not available.
func requireGit(t *testing.T) {
	t.Helper()
	requireTool(t, "git")
}

// requireContainerRuntime skips the test if neither docker nor podman is
// available on PATH.
func requireContainerRuntime(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err == nil {
		return
	}
	if _, err := exec.LookPath("podman"); err == nil {
		return
	}
	t.Skip("no container runtime (docker or podman) found on PATH")
}

// repoRoot returns the root of the bomly-cli repo.
func repoRoot(t *testing.T) string {
	t.Helper()
	// We are at test/smoke/ — go up two levels.
	here, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(here, "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}
