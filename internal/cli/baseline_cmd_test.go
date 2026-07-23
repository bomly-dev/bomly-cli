package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/baseline"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBaselineInspectJSON(t *testing.T) {
	project := t.TempDir()
	path := project + "/.bomly/baseline.json"
	document := baseline.NewDocument([]sdk.Finding{{ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0"}}, nil)
	if err := baseline.WriteAtomic(path, document, false); err != nil {
		t.Fatal(err)
	}
	cmd := newBaselineInspectCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--path", project, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"schema_version": "bomly.finding-baseline/v1"`) {
		t.Fatalf("inspect output = %s", stdout.String())
	}
}

func TestBaselineCommandExposesLifecycleOperations(t *testing.T) {
	cmd := newBaselineCmd()
	want := map[string]bool{"create": false, "update": false, "prune": false, "inspect": false}
	for _, child := range cmd.Commands() {
		if _, ok := want[child.Name()]; ok {
			want[child.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("baseline command missing %q", name)
		}
	}
}

func TestBaselineLifecycleCommandsExposeExecutionFlags(t *testing.T) {
	root, err := newRootCmd("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"create", "update", "prune"} {
		cmd, _, err := root.Find([]string{"baseline", action})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"install-first", "install-arg"} {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("baseline %s missing --%s", action, name)
			}
		}
	}
}

func TestBaselineMutationRequiresLocalProject(t *testing.T) {
	for _, configured := range []config.Resolved{
		{URL: "https://example.test/project.git"},
		{Image: "example.test/project:latest"},
		{SBOM: true},
	} {
		if err := validateBaselineMutationTarget(configured); err == nil {
			t.Fatalf("validateBaselineMutationTarget(%+v) returned nil", configured)
		}
	}
	if err := validateBaselineMutationTarget(config.Resolved{Path: t.TempDir()}); err != nil {
		t.Fatalf("local project rejected: %v", err)
	}
}

func TestBaselineLifecycleCommandsPreserveAtomicPolicyState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BOMLY_OSV_CACHE_DIR", filepath.Join(home, "cache", "osv"))
	t.Setenv("BOMLY_OSV_CACHE_TTL", "1ns")

	var failRequests bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if failRequests {
			http.Error(w, "fixture unavailable", http.StatusServiceUnavailable)
			return
		}
		if request.URL.Path != "/v1/querybatch" {
			http.NotFound(w, request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var query struct {
			Queries []json.RawMessage `json:"queries"`
		}
		if err := json.Unmarshal(body, &query); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]map[string]any, len(query.Queries))
		for idx := range results {
			results[idx] = map[string]any{"vulns": []any{}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	t.Cleanup(server.Close)
	t.Setenv("BOMLY_OSV_API_BASE", server.URL)

	project := t.TempDir()
	writeBaselinePackageJSON(t, project, "18.2.0", false)
	baselinePath := filepath.Join(project, ".bomly", "baseline.json")

	run := func(args ...string) (string, string, error) {
		t.Helper()
		root, err := newRootCmd("test")
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(args)
		err = root.Execute()
		return stdout.String(), stderr.String(), err
	}
	lifecycleArgs := func(action string, denied ...string) []string {
		args := []string{
			"baseline", action,
			"-vv",
			"--path", project,
			"--ecosystems", "npm",
			"--detectors", "npm-detector",
			"--enrich",
			"--matchers", "osv",
			"--auditors", "package",
		}
		for _, purl := range denied {
			args = append(args, "--deny-package", purl)
		}
		return args
	}

	stdout, stderr, err := run(lifecycleArgs("create", "pkg:npm/react@18.2.0")...)
	if err != nil {
		t.Fatalf("baseline create: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Create baseline") {
		t.Fatalf("create output = %q\nstderr:\n%s", stdout, stderr)
	}
	created, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Entries) != 1 || created.Entries[0].PackageRef != "pkg:npm/react@18.2.0" {
		t.Fatalf("created baseline = %#v\nstderr:\n%s", created, stderr)
	}

	beforeCreateRetry, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(lifecycleArgs("create", "pkg:npm/react@18.2.0")...); err == nil {
		t.Fatal("second baseline create unexpectedly overwrote the document")
	}
	afterCreateRetry, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterCreateRetry, beforeCreateRetry) {
		t.Fatal("failed create changed the existing baseline")
	}

	writeBaselinePackageJSON(t, project, "19.0.0", true)
	if _, stderr, err := run(lifecycleArgs("update", "pkg:npm/zod@3.23.0")...); err != nil {
		t.Fatalf("baseline update: %v\nstderr:\n%s", err, stderr)
	}
	updated, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Entries) != 2 {
		t.Fatalf("updated baseline entries = %#v", updated.Entries)
	}

	if _, stderr, err := run(lifecycleArgs("prune", "pkg:npm/zod@3.23.0")...); err != nil {
		t.Fatalf("baseline prune: %v\nstderr:\n%s", err, stderr)
	}
	pruned, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.Entries) != 1 || pruned.Entries[0].PackageRef != "pkg:npm/zod@3.23.0" {
		t.Fatalf("pruned baseline = %#v", pruned.Entries)
	}

	beforeDegraded, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	failRequests = true
	if err := os.RemoveAll(filepath.Join(home, "cache", "osv")); err != nil {
		t.Fatal(err)
	}
	_, degradedStderr, err := run(lifecycleArgs("update", "pkg:npm/zod@3.23.0")...)
	if err == nil || !strings.Contains(err.Error(), "degraded-coverage warning") {
		t.Fatalf("degraded update error = %v\nstderr:\n%s", err, degradedStderr)
	}
	afterDegraded, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterDegraded, beforeDegraded) {
		t.Fatal("degraded update changed the existing baseline")
	}
}

func writeBaselinePackageJSON(t *testing.T, project, reactVersion string, includeZod bool) {
	t.Helper()
	dependencies := map[string]string{"react": reactVersion}
	resolvedDependencies := map[string]any{
		"react": map[string]string{"version": reactVersion},
	}
	packages := map[string]any{
		"":                   map[string]any{"name": "demo-app", "version": "1.0.0", "dependencies": dependencies},
		"node_modules/react": map[string]string{"version": reactVersion},
	}
	if includeZod {
		dependencies["zod"] = "3.23.0"
		resolvedDependencies["zod"] = map[string]string{"version": "3.23.0"}
		packages["node_modules/zod"] = map[string]string{"version": "3.23.0"}
	}
	document := map[string]any{
		"name": "demo-app", "version": "1.0.0", "dependencies": dependencies,
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	lockDocument := map[string]any{
		"name":            "demo-app",
		"version":         "1.0.0",
		"lockfileVersion": 2,
		"requires":        true,
		"packages":        packages,
		"dependencies":    resolvedDependencies,
	}
	lockData, err := json.Marshal(lockDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), append(lockData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
