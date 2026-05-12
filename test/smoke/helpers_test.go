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
	"regexp"
	"runtime"
	"sort"
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
	if smokeGOPATH != "" {
		cmd.Env = append(cmd.Env, "GOPATH="+smokeGOPATH)
	}
	if smokeGOMODCACHE != "" {
		cmd.Env = append(cmd.Env, "GOMODCACHE="+smokeGOMODCACHE)
	}
	if smokeGOCACHE != "" {
		cmd.Env = append(cmd.Env, "GOCACHE="+smokeGOCACHE)
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

	// Normalize synthetic project IDs (e.g. pkg:maven/bomly-git-NNNNNN) that
	// are derived from a non-deterministic hash of the temp clone directory.
	normalizeSyntheticIDs(obj)

	// Remove synthetic root packages (packages whose id is not a PURL) that
	// the API sometimes includes and sometimes omits, making goldens flaky.
	removeNonPURLPackages(obj)

	// Sort string-slice fields whose order is non-deterministic across runs
	// (e.g. the dependencies array within a package).
	sortStringSlices(obj)

	// Sort packages arrays within manifests by id so the order is stable
	// across runs (the server may return packages in any order).
	sortPackagesByID(obj)

	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatalf("normalizeJSON: marshal: %v", err)
	}
	return append(out, '\n')
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

// normalizeReachability scrubs volatile analyzer fields so reachability smoke
// goldens remain stable across source checkouts and analyzer versions.
func normalizeReachability(node any) {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			switch key {
			case "analyzed_at":
				v[key] = "<timestamp>"
			case "line", "column":
				if _, ok := val.(float64); ok {
					v[key] = float64(0)
				}
			case "file":
				if s, ok := val.(string); ok {
					v[key] = normalizeReachabilityFile(s)
				}
			default:
				normalizeReachability(val)
			}
		}
	case []any:
		for _, child := range v {
			normalizeReachability(child)
		}
	}
}

func normalizeReachabilityFile(value string) string {
	value = filepath.ToSlash(strings.TrimSpace(value))
	if value == "" || !filepath.IsAbs(value) {
		return value
	}
	parts := strings.Split(value, "/")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return filepath.Base(value)
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

// reBomlyGitID matches synthetic project PURLs like "pkg:maven/bomly-git-806792449"
// whose numeric suffix is derived from a non-deterministic hash of the temp clone dir.
var reBomlyGitID = regexp.MustCompile(`(pkg:[^/]+/bomly-git)-\d+`)

// reBomlyGitName matches bare synthetic names like "bomly-git-806792449" (used
// in the "name" field of a package when no PURL prefix is present).
var reBomlyGitName = regexp.MustCompile(`(bomly-git)-\d+`)

// normalizeSyntheticIDs replaces non-deterministic bomly-git-NNNNNN IDs with a
// stable placeholder throughout the JSON tree.
func normalizeSyntheticIDs(node any) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok {
				if reBomlyGitID.MatchString(s) {
					v[k] = reBomlyGitID.ReplaceAllString(s, "${1}-<normalized>")
				} else if reBomlyGitName.MatchString(s) {
					v[k] = reBomlyGitName.ReplaceAllString(s, "${1}-<normalized>")
				}
			} else {
				normalizeSyntheticIDs(val)
			}
		}
	case []any:
		for _, child := range v {
			normalizeSyntheticIDs(child)
		}
	}
}

// sortPackagesByID sorts the "packages" array within each manifest by the
// "id" field so that the order is stable across runs regardless of server
// response ordering.
func sortPackagesByID(obj map[string]any) {
	// scan response: obj.manifests[].packages[]
	if manifests, ok := obj["manifests"].([]any); ok {
		for _, m := range manifests {
			if mmap, ok := m.(map[string]any); ok {
				sortObjSliceByKey(mmap, "packages", "id")
			}
		}
	}
	// diff response: obj.results.manifests[].packages[]
	if results, ok := obj["results"].(map[string]any); ok {
		if manifests, ok := results["manifests"].([]any); ok {
			for _, m := range manifests {
				if mmap, ok := m.(map[string]any); ok {
					sortObjSliceByKey(mmap, "packages", "id")
				}
			}
		}
	}
	// explain response: obj.targets[].packages[]
	if targets, ok := obj["targets"].([]any); ok {
		for _, tgt := range targets {
			if tmap, ok := tgt.(map[string]any); ok {
				sortObjSliceByKey(tmap, "packages", "id")
			}
		}
	}
}

// sortObjSliceByKey sorts an []any of map[string]any objects stored at
// parent[key] by the value of sortField within each object.
func sortObjSliceByKey(parent map[string]any, key, sortField string) {
	arr, ok := parent[key].([]any)
	if !ok || len(arr) == 0 {
		return
	}
	sort.SliceStable(arr, func(i, j int) bool {
		mi, oki := arr[i].(map[string]any)
		mj, okj := arr[j].(map[string]any)
		if !oki || !okj {
			return false
		}
		si, _ := mi[sortField].(string)
		sj, _ := mj[sortField].(string)
		return si < sj
	})
}

// sortStringSlices sorts any []string values (or []any values whose elements
// are all strings) found anywhere in the JSON tree. This stabilises fields
// like the per-package "dependencies" array whose order varies between runs.
func sortStringSlices(node any) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			switch arr := val.(type) {
			case []any:
				// Check if all elements are strings.
				allStrings := len(arr) > 0
				for _, el := range arr {
					if _, ok := el.(string); !ok {
						allStrings = false
						break
					}
				}
				if allStrings {
					strs := make([]string, len(arr))
					for i, el := range arr {
						strs[i] = el.(string)
					}
					sort.Strings(strs)
					sorted := make([]any, len(strs))
					for i, s := range strs {
						sorted[i] = s
					}
					v[k] = sorted
				} else {
					sortStringSlices(arr)
				}
			default:
				sortStringSlices(val)
			}
		}
	case []any:
		for _, child := range v {
			sortStringSlices(child)
		}
	}
}

// removeNonPURLPackages filters out packages whose "id" field is not a PURL
// (i.e. does not start with "pkg:"). Such packages are synthetic root packages
// that the API sometimes includes and sometimes omits, making goldens flaky.
func removeNonPURLPackages(obj map[string]any) {
	filterPkgs := func(packages []any) []any {
		out := packages[:0:len(packages)]
		for _, p := range packages {
			pm, ok := p.(map[string]any)
			if !ok {
				out = append(out, p)
				continue
			}
			id, _ := pm["id"].(string)
			if strings.HasPrefix(id, "pkg:") {
				out = append(out, p)
			}
		}
		return out
	}
	applyToManifests := func(manifests []any) {
		for _, m := range manifests {
			mmap, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if pkgs, ok := mmap["packages"].([]any); ok {
				mmap["packages"] = filterPkgs(pkgs)
			}
		}
	}
	// scan response
	if manifests, ok := obj["manifests"].([]any); ok {
		applyToManifests(manifests)
	}
	// diff response
	if results, ok := obj["results"].(map[string]any); ok {
		if manifests, ok := results["manifests"].([]any); ok {
			applyToManifests(manifests)
			for _, m := range manifests {
				mmap, ok := m.(map[string]any)
				if !ok {
					continue
				}
				for _, key := range []string{"added", "removed"} {
					if changes, ok := mmap[key].([]any); ok {
						filtered := filterNonPURLDiffChanges(changes)
						if len(filtered) == 0 {
							delete(mmap, key)
						} else {
							mmap[key] = filtered
						}
					}
				}
			}
			normalizeDiffSummary(obj)
		}
		// diff packages section: results.packages.{added,changed,removed}[]
		if pkgSections, ok := results["packages"].(map[string]any); ok {
			for _, sec := range []string{"added", "changed", "removed"} {
				if pkgs, ok := pkgSections[sec].([]any); ok {
					pkgSections[sec] = filterPkgs(pkgs)
				}
			}
		}
	}
	// explain response
	if targets, ok := obj["targets"].([]any); ok {
		applyToManifests(targets)
	}
}

func filterNonPURLDiffChanges(changes []any) []any {
	out := changes[:0:len(changes)]
	for _, change := range changes {
		cm, ok := change.(map[string]any)
		if !ok {
			out = append(out, change)
			continue
		}
		pm, ok := cm["package"].(map[string]any)
		if !ok {
			out = append(out, change)
			continue
		}
		id, _ := pm["id"].(string)
		if strings.HasPrefix(id, "pkg:") {
			out = append(out, change)
		}
	}
	return out
}

func normalizeDiffSummary(obj map[string]any) {
	results, ok := obj["results"].(map[string]any)
	if !ok {
		return
	}
	manifests, ok := results["manifests"].([]any)
	if !ok {
		return
	}
	summary, ok := obj["summary"].(map[string]any)
	if !ok {
		return
	}
	addedPackages := 0
	changedPackages := 0
	removedPackages := 0
	for _, m := range manifests {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		if changes, ok := mm["added"].([]any); ok {
			addedPackages += len(changes)
		}
		if changes, ok := mm["changed"].([]any); ok {
			changedPackages += len(changes)
		}
		if changes, ok := mm["removed"].([]any); ok {
			removedPackages += len(changes)
		}
	}
	summary["added_package_count"] = float64(addedPackages)
	summary["changed_package_count"] = float64(changedPackages)
	summary["removed_package_count"] = float64(removedPackages)
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
