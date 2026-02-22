package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	syftdetector "github.com/bomly-dev/bomly-cli/internal/detectors/syft"
)

func TestRoot_RegistersCoreCommands(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	for _, commandName := range []string{"explain", "scan", "diff", "version"} {
		cmd, _, err := root.Find([]string{commandName})
		if err != nil {
			t.Fatalf("root.Find(%q) error = %v", commandName, err)
		}
		if cmd == nil || cmd.Name() != commandName {
			t.Fatalf("expected command %q, got %#v", commandName, cmd)
		}
	}
}

func TestRoot_FlagOnlyInvocationRequiresCommand(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--verbose"})

	err = normalizeExecuteError(root.Execute())
	if err == nil {
		t.Fatal("expected flag-only invocation to fail")
	}
	if ExitCode(err) != exitCodeInvalidInput {
		t.Fatalf("expected invalid input exit code, got %d (err=%v)", ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "a command is required when using flags") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
}

func TestRoot_HelpFlagWithoutCommandStillWorks(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}
	helpText := stdout.String()
	if !strings.Contains(helpText, "Usage:") {
		t.Fatalf("expected help output, got %q", helpText)
	}
	if !strings.Contains(helpText, "  bomly [command]") {
		t.Fatalf("expected command-only usage line, got %q", helpText)
	}
	if strings.Contains(helpText, "  bomly [flags]") {
		t.Fatalf("expected help to omit root [flags] usage line, got %q", helpText)
	}
}

func TestRoot_VersionFlagWithoutCommandStillWorks(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0.9.0-test") {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
}

func TestRoot_VersionCommandWithoutFlagsStillWorks(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0.9.0-test") {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
}

func TestRoot_ScanCommand_ScansRepoURLAtRef(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, _ := createGitNPMRepoHistory(t)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--url", repoDir, "--ref", baseSHA, "--ecosystems", "npm", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	packages, ok := scanPayloadPackages(payload)
	if !ok {
		t.Fatalf("expected manifests payload, got %#v", payload["manifests"])
	}
	packageIDs := make([]string, 0, len(packages))
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := pkg["id"].(string)
		packageIDs = append(packageIDs, id)
	}
	if !containsString(packageIDs, "pkg:npm/react@18.2.0") {
		t.Fatalf("expected base ref dependencies in graph, got %#v", packageIDs)
	}
	if containsString(packageIDs, "pkg:npm/zod@3.23.0") {
		t.Fatalf("expected base ref to exclude head-only dependency, got %#v", packageIDs)
	}
}

func TestRoot_DiffCommand_JSONOutput(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, headSHA := createGitNPMRepoHistory(t)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--path", repoDir, "--ecosystems", "npm", "--base", baseSHA, "--head", headSHA, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["command"]; got != "diff" {
		t.Fatalf("expected diff command, got %#v", got)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("unexpected diff summary: %#v", summary)
	}
	if summary["unchanged_manifest_count"] == nil {
		t.Fatalf("expected unchanged manifest count, got %#v", summary)
	}
	results, ok := payload["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results object, got %#v", payload["results"])
	}
	manifests, _ := results["manifests"].([]any)
	if len(manifests) == 0 {
		t.Fatalf("unexpected diff manifests: %#v", results)
	}
	if !containsManifestPackageChange(manifests, "changed", "zod", "3.23.0", "added") {
		t.Fatalf("expected zod addition in %#v", manifests)
	}
	if !containsManifestUpdatedPackageChange(manifests, "changed", "react", "19.0.0", "18.2.0") {
		t.Fatalf("expected react update in %#v", manifests)
	}
}

func TestRoot_DiffCommand_AuditUsesResolvedGitRefs(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, headSHA := createGitNPMRepoHistory(t)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"diff",
		"--path", repoDir,
		"--ecosystems", "npm",
		"--base", baseSHA,
		"--head", headSHA,
		"--audit",
		"--matchers", "grype,osv",
		"--auditors", "severity-policy",
		"--format", "json",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if payload["audit"] == nil {
		t.Fatalf("expected audit payload, got %#v", payload)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("unexpected diff summary: %#v", summary)
	}
}

func TestRoot_ScanCommand_QuietSuppressesVerboseLogs(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{\n  \"name\": \"demo-app\",\n  \"version\": \"1.0.0\"\n}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{"name":"demo-app","version":"1.0.0","dependencies":{"react":{"version":"18.2.0"}}}`)

	runScan := func(args ...string) (string, string) {
		t.Helper()
		root, err := newRootCmd("0.9.0-test")
		if err != nil {
			t.Fatalf("newRootCmd() error = %v", err)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
		}
		return stdout.String(), stderr.String()
	}

	stdout, stderr := runScan("scan", "--path", projectDir, "--ecosystems", "npm", "--format", "json", "-vv")
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("expected stdout payload from verbose scan")
	}
	if !strings.Contains(stderr, "Resolved options") {
		t.Fatalf("expected verbose scan to emit debug logs, got %q", stderr)
	}

	stdout, stderr = runScan("scan", "--path", projectDir, "--ecosystems", "npm", "--format", "json", "--quiet")
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("expected stdout payload from quiet scan")
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("expected quiet scan to suppress non-error stderr output, got %q", stderr)
	}
}

func TestRoot_DiffCommand_SupportsBranchNames(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, _ := createGitNPMRepoHistory(t)
	runGit(t, repoDir, "branch", "master")

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--path", repoDir, "--ecosystems", "npm", "--base", baseSHA, "--head", "master", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("unexpected branch-based diff summary: %#v", summary)
	}
}

func TestRoot_DiffCommand_SupportsRepoURL(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, headSHA := createGitNPMRepoHistory(t)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--url", repoDir, "--ecosystems", "npm", "--base", baseSHA, "--head", headSHA, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["path"] != repoDir {
		t.Fatalf("expected project path %q, got %#v", repoDir, project["path"])
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("unexpected diff summary: %#v", summary)
	}
}

func TestRoot_DiffCommand_SupportsRepoURLRemoteBranchNames(t *testing.T) {
	requireGit(t)
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	setDynamicFakeNPMOnPath(t)
	repoDir, baseSHA, headSHA := createGitNPMRepoHistory(t)
	runGit(t, repoDir, "branch", "feature", headSHA)
	runGit(t, repoDir, "reset", "--hard", baseSHA)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--url", repoDir, "--ecosystems", "npm", "--base", baseSHA, "--head", "feature", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("unexpected diff summary: %#v", summary)
	}
}

func TestRoot_DiffCommand_SupportsContainerTargets(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	baseDir, err := os.MkdirTemp("", "bomly-diff-container-base-*")
	if err != nil {
		t.Fatalf("create base dir: %v", err)
	}
	headDir, err := os.MkdirTemp("", "bomly-diff-container-head-*")
	if err != nil {
		t.Fatalf("create head dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "package.json"), []byte(`{"name":"demo-app","version":"1.0.0","dependencies":{"react":"18.2.0"}}`), 0o644); err != nil {
		t.Fatalf("write base package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "package-lock.json"), []byte(`{"name":"demo-app","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"demo-app","version":"1.0.0","dependencies":{"react":"18.2.0"}},"node_modules/react":{"version":"18.2.0"}},"dependencies":{"react":{"version":"18.2.0"}}}`), 0o644); err != nil {
		t.Fatalf("write base package-lock.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headDir, "package.json"), []byte(`{"name":"demo-app","version":"1.0.0","dependencies":{"react":"19.0.0","zod":"3.23.0"}}`), 0o644); err != nil {
		t.Fatalf("write head package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headDir, "package-lock.json"), []byte(`{"name":"demo-app","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"demo-app","version":"1.0.0","dependencies":{"react":"19.0.0","zod":"3.23.0"}},"node_modules/react":{"version":"19.0.0"},"node_modules/zod":{"version":"3.23.0"}},"dependencies":{"react":{"version":"19.0.0"},"zod":{"version":"3.23.0"}}}`), 0o644); err != nil {
		t.Fatalf("write head package-lock.json: %v", err)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--container", "example/demo", "--base", baseDir, "--head", headDir, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["path"] != "example/demo" {
		t.Fatalf("expected container project path, got %#v", project["path"])
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", payload["summary"])
	}
	if summary["changed_manifest_count"] == float64(0) {
		t.Fatalf("expected at least one changed manifest, got %#v", summary)
	}
	results, ok := payload["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results object, got %#v", payload["results"])
	}
	manifests, _ := results["manifests"].([]any)
	if !containsManifestUpdatedPackageChange(manifests, "changed", "react", "19.0.0", "18.2.0") {
		t.Fatalf("expected react update in %#v", manifests)
	}
	if !containsManifestPackageChange(manifests, "changed", "zod", "3.23.0", "added") {
		t.Fatalf("expected zod addition in %#v", manifests)
	}
}

func TestRoot_DiffCommand_RequiresBaseAndHeadFlags(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff"})

	err = normalizeExecuteError(root.Execute())
	if err == nil {
		t.Fatal("expected missing required flag error")
	}
	if ExitCode(err) != exitCodeInvalidInput {
		t.Fatalf("expected invalid input exit code, got %d (err=%v)", ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "--base is required") {
		t.Fatalf("expected required flag error, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
}

func TestRoot_ScanCommand_InteractiveRejectsJSONFormat(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetIn(bytes.NewBuffer(nil))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--interactive", "--format", "json"})

	err = normalizeExecuteError(root.Execute())
	if err == nil {
		t.Fatal("expected interactive format validation error")
	}
	if ExitCode(err) != exitCodeInvalidInput {
		t.Fatalf("expected invalid input exit code, got %d (err=%v)", ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "--interactive cannot be combined with --format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoot_DiffCommand_InteractiveRejectsJSONFormat(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetIn(bytes.NewBuffer(nil))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"diff", "--interactive", "--format", "json", "--base", "base", "--head", "head"})

	err = normalizeExecuteError(root.Execute())
	if err == nil {
		t.Fatal("expected interactive format validation error")
	}
	if ExitCode(err) != exitCodeInvalidInput {
		t.Fatalf("expected invalid input exit code, got %d (err=%v)", ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "--interactive cannot be combined with --format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoot_WhyCommand_JSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    },
    "zod": {
      "version": "3.23.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		fatalf := t.Fatalf
		fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "loose-envify", "--path", projectDir, "--ecosystems", "npm", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["command"]; got != "explain" {
		t.Fatalf("expected command explain, got %#v", got)
	}
	if got := payload["schema_version"]; got != "1.0" {
		t.Fatalf("expected schema version 1.0, got %#v", got)
	}
}

func TestRoot_WhyCommand_DefaultTextOutputUsesTree(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "loose-envify", "--path", projectDir, "--ecosystems", "npm"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	out := stdout.String()
	plainOut := stripANSI(out)
	projectName := filepath.Base(projectDir)
	for _, want := range []string{
		"Dependency Explanation",
		"Component:",
		"loose-envify@1.4.0",
		"Project:",
		projectName,
		"Path count:",
		"demo-app@1.0.0",
		"\\- react@18.2.0",
		"   \\- loose-envify@1.4.0 [analyzed] (transitive)",
	} {
		if !strings.Contains(plainOut, want) {
			t.Fatalf("expected text output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(plainOut, "->") {
		t.Fatalf("expected tree output instead of flattened path, got:\n%s", out)
	}
}

func TestRoot_WhyCommand_FallsBackToSyftWhenNPMUnavailable(t *testing.T) {
	if !syftdetector.IsBuiltin() {
		t.Skip("test requires builtin syft library (PATH is cleared during test)")
	}
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
		"name": "demo-app",
		"version": "1.0.0",
		"dependencies": {
			"react": "18.2.0"
		}
	}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"name": "demo-app",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"requires": true,
		"packages": {
			"": {
				"name": "demo-app",
				"version": "1.0.0",
				"dependencies": {
					"react": "18.2.0"
				}
			},
			"node_modules/react": {
				"version": "18.2.0"
			}
		},
		"dependencies": {
			"react": {
				"version": "18.2.0"
			}
		}
	}
`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	t.Setenv("PATH", "")

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "react", "--path", projectDir, "--ecosystems", "npm", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	dependency, ok := payload["dependency"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependency object, got %#v", payload["dependency"])
	}
	if dependency["name"] != "react" {
		t.Fatalf("expected react dependency, got %#v", dependency)
	}
	paths, ok := payload["paths"].([]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("expected one explain path, got %#v", payload["paths"])
	}
}

func TestRoot_ScanCommand_SBOMJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "-o", "spdx-json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["spdxVersion"]; got == nil {
		t.Fatalf("expected SPDX document, got %#v", payload)
	}
	packages, ok := payload["packages"].([]any)
	if !ok || len(packages) < 2 {
		t.Fatalf("expected SPDX packages, got %#v", payload["packages"])
	}
}

func TestRoot_ScanCommand_WritesMultipleSBOMFormatsToFiles(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    }
  }
}`)

	spdxPath := filepath.Join(t.TempDir(), "spdx.json")
	cdxPath := filepath.Join(t.TempDir(), "cdx.json")

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "-o", "spdx-json=" + spdxPath, "-o", "cyclonedx-json=" + cdxPath})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout when writing files, got %q", stdout.String())
	}

	spdxData, err := os.ReadFile(spdxPath)
	if err != nil {
		t.Fatalf("read SPDX file: %v", err)
	}
	var spdxDoc map[string]any
	if err := json.Unmarshal(spdxData, &spdxDoc); err != nil {
		t.Fatalf("unmarshal SPDX file: %v", err)
	}
	if got := spdxDoc["spdxVersion"]; got == nil {
		t.Fatalf("expected SPDX document, got %#v", spdxDoc)
	}

	cdxData, err := os.ReadFile(cdxPath)
	if err != nil {
		t.Fatalf("read CycloneDX file: %v", err)
	}
	var cdxDoc map[string]any
	if err := json.Unmarshal(cdxData, &cdxDoc); err != nil {
		t.Fatalf("unmarshal CycloneDX file: %v", err)
	}
	if got := cdxDoc["bomFormat"]; got != "CycloneDX" {
		t.Fatalf("expected CycloneDX document, got %#v", cdxDoc)
	}
}

func TestRoot_ScanCommand_InteractiveRejectsSBOMOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	projectDir := t.TempDir()
	setDynamicFakeNPMOnPath(t)
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{\"name\":\"demo-app\",\"version\":\"1.0.0\",\"dependencies\":{\"react\":\"18.2.0\"}}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte("{\"name\":\"demo-app\",\"version\":\"1.0.0\",\"lockfileVersion\":2,\"requires\":true,\"packages\":{\"\":{\"name\":\"demo-app\",\"version\":\"1.0.0\",\"dependencies\":{\"react\":\"18.2.0\"}},\"node_modules/react\":{\"version\":\"18.2.0\"}},\"dependencies\":{\"react\":{\"version\":\"18.2.0\"}}}\n"), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetIn(bytes.NewBuffer(nil))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--interactive", "--path", projectDir, "--ecosystems", "npm", "-o", "spdx-json"})

	err = normalizeExecuteError(root.Execute())
	if err == nil {
		t.Fatal("expected interactive terminal validation error")
	}
	if ExitCode(err) != exitCodeInvalidInput {
		t.Fatalf("expected invalid input exit code, got %d (err=%v)", ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "--interactive requires a terminal stdin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoot_ScanCommand_JSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["command"]; got != "scan" {
		t.Fatalf("expected command scan, got %#v", got)
	}
	packages, ok := scanPayloadPackages(payload)
	if !ok || len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %#v", payload["manifests"])
	}
	if !containsPackageWithScope(packages, "react", "runtime") {
		t.Fatalf("expected json output to include runtime scope, got %#v", packages)
	}
	if !containsPackageDependency(packages, "demo-app", "pkg:npm/react@18.2.0") {
		t.Fatalf("expected demo-app package dependencies to include react, got %#v", packages)
	}
	if !containsPackageDependencies(packages, "react", []string{}) {
		t.Fatalf("expected leaf package dependencies to serialize as an empty array, got %#v", packages)
	}
}

func TestRoot_ScanCommand_JSONOutputIncludesScopeAndFilter(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  },
  "devDependencies": {
    "vitest": "^2.0.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    },
    "vitest": {
      "version": "2.0.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--scope", "development", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	packages, ok := scanPayloadPackages(payload)
	if !ok || len(packages) != 2 {
		t.Fatalf("expected filtered root + development dependency, got %#v", payload["manifests"])
	}
	if !containsPackageWithScope(packages, "vitest", "development") {
		t.Fatalf("expected development-scoped vitest package, got %#v", packages)
	}
	if containsPackageName(packages, "react") {
		t.Fatalf("expected runtime-scoped react to be filtered out, got %#v", packages)
	}
}

func TestRoot_StartupLogsResolvedOptionsWhenVerbose(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--format", "json", "-vv"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	logText := stderr.String()
	for _, want := range []string{
		"Resolved options",
		`"path":`,
		`"ecosystems": "npm"`,
		`"verbose": true`,
		`"verbosity": 2`,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("expected stderr log to contain %q, got:\n%s", want, logText)
		}
	}
}

func TestRoot_ScanCommand_TreeFormatRejected(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--format", "tree"})

	err = root.Execute()
	if err == nil {
		t.Fatal("expected scan tree format to be rejected")
	}
	if !strings.Contains(err.Error(), `parse format: unsupported format "tree"`) {
		t.Fatalf("expected tree format error, got %v", err)
	}
}

func TestRoot_ScanCommand_TextReportOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    },
    "zod": {
      "version": "3.23.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--format", "text"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Dependency report for demo-app") {
		t.Fatalf("expected scan header, got: %s", out)
	}
	for _, want := range []string{
		"Executive Summary",
		"Manifests",
		"package.json",
		"Dependency Inventory",
		"License Overview",
		"PACKAGE",
		"VERSION",
		"SCOPE",
		"RELATIONSHIP",
		"demo-app",
		"1.0.0",
		"root",
		"react",
		"18.2.0",
		"direct",
		"zod",
		"3.23.0",
		"loose-envify",
		"1.4.0",
		"transitive",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected text report output to contain %q, got: %s", want, out)
		}
	}
	rootIdx := strings.Index(out, "demo-app")
	directIdx := strings.Index(out, "react")
	transitiveIdx := strings.Index(out, "loose-envify")
	if rootIdx == -1 || directIdx == -1 || transitiveIdx == -1 {
		t.Fatalf("expected root, direct, and transitive rows in output, got: %s", out)
	}
	if !(rootIdx < directIdx && directIdx < transitiveIdx) {
		t.Fatalf("expected root/direct/transitive order, got: %s", out)
	}
}

func TestRoot_ScanCommand_TextOutputIncludesScope(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  }
}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	setFakeNPMOnPath(t, `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0"
    }
  }
}`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "npm", "--format", "text"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "react") || !strings.Contains(out, "runtime") {
		t.Fatalf("expected scoped report output, got: %s", out)
	}
}

func TestRoot_WhyCommand_GradleWrapper_JSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.gradle"), []byte("plugins { id 'java' }\n"), 0o644); err != nil {
		t.Fatalf("write build.gradle: %v", err)
	}
	writeFakeGradleWrapper(t, projectDir, `runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework:spring-core:6.1.1
|    \--- org.springframework:spring-jcl:6.1.1
\--- org.slf4j:slf4j-api:2.0.12
`)
	setFailingFakeGradleOnPath(t)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "org.springframework:spring-jcl", "--path", projectDir, "--ecosystems", "gradle", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["ecosystem"] != "maven" {
		t.Fatalf("expected maven ecosystem, got %#v", project["ecosystem"])
	}
	dependency, ok := payload["dependency"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependency object, got %#v", payload["dependency"])
	}
	if dependency["id"] != "org.springframework:spring-jcl@6.1.1" {
		t.Fatalf("expected gradle dependency id, got %#v", dependency["id"])
	}
}

func TestRoot_ScanCommand_GradlePathFallback_SBOMJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "settings.gradle.kts"), []byte("rootProject.name = \"demo-gradle\"\n"), 0o644); err != nil {
		t.Fatalf("write settings.gradle.kts: %v", err)
	}
	setFakeGradleOnPath(t, `runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.slf4j:slf4j-api:2.0.12
\--- com.google.guava:guava:33.0.0-jre
`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "-o", "spdx-json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["spdxVersion"]; got == nil {
		t.Fatalf("expected SPDX document, got %#v", payload)
	}
}

func TestRoot_WhyCommand_MavenWrapper_JSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "pom.xml"), []byte("<project/>\n"), 0o644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	writeFakeMavenWrapper(t, projectDir, `1 com.example:demo-app:jar:1.0.0
2 ch.qos.logback:logback-classic:jar:1.5.6:compile
3 org.slf4j:slf4j-api:jar:2.0.13:compile
#
1 2 compile
2 3 compile
`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "org.slf4j:slf4j-api", "--path", projectDir, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["ecosystem"] != "maven" {
		t.Fatalf("expected inferred ecosystem maven, got %#v", project["ecosystem"])
	}
	dependency, ok := payload["dependency"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependency object, got %#v", payload["dependency"])
	}
	if dependency["id"] != "org.slf4j:slf4j-api@2.0.13" {
		t.Fatalf("expected Maven dependency id, got %#v", dependency["id"])
	}
}

func TestRoot_ScanCommand_MavenSBOMJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "pom.xml"), []byte("<project/>\n"), 0o644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}
	setFakeMavenOnPath(t, `1 com.example:demo-app:jar:1.0.0
2 org.slf4j:slf4j-api:jar:2.0.13:compile
#
1 2 compile
`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"scan", "--path", projectDir, "--ecosystems", "maven", "-o", "spdx-json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	if got := payload["spdxVersion"]; got == nil {
		t.Fatalf("expected SPDX document, got %#v", payload)
	}
}

func TestRoot_WhyCommand_GoModules_JSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte(`module example.com/demo

go 1.22.0

require rsc.io/quote v1.5.2
`), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	setFakeGoOnPath(t, `{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["rsc.io/quote"]}
{"ImportPath":"rsc.io/quote","Module":{"Path":"rsc.io/quote","Version":"v1.5.2"},"Imports":["golang.org/x/text/language"]}
{"ImportPath":"golang.org/x/text/language","Module":{"Path":"golang.org/x/text","Version":"v0.14.0"}}
`)

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "golang.org/x/text", "--path", projectDir, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["ecosystem"] != "go" {
		t.Fatalf("expected inferred ecosystem go, got %#v", project["ecosystem"])
	}
	dependency, ok := payload["dependency"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependency object, got %#v", payload["dependency"])
	}
	if dependency["id"] != "golang.org/x/text@v0.14.0" {
		t.Fatalf("expected Go dependency id, got %#v", dependency["id"])
	}
	paths, ok := payload["paths"].([]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("expected one explain path, got %#v", payload["paths"])
	}
}

func TestRoot_WhyCommand_GoModulesFallbackWithoutGoCLI(t *testing.T) {
	if !syftdetector.IsBuiltin() {
		t.Skip("test requires builtin syft library (PATH is cleared during test)")
	}
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempHome)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte(`module example.com/demo

go 1.22.0

require (
	github.com/google/uuid v1.6.0
	rsc.io/quote v1.5.2
)
`), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	t.Setenv("PATH", "")

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explain", "github.com/google/uuid", "--path", projectDir, "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v; stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		t.Fatalf("expected project object, got %#v", payload["project"])
	}
	if project["ecosystem"] != "go" {
		t.Fatalf("expected inferred ecosystem go, got %#v", project["ecosystem"])
	}
	dependency, ok := payload["dependency"].(map[string]any)
	if !ok {
		t.Fatalf("expected dependency object, got %#v", payload["dependency"])
	}
	if dependency["name"] != "github.com/google/uuid" {
		t.Fatalf("expected Go dependency name, got %#v", dependency["name"])
	}
	if dependency["version"] != "v1.6.0" {
		t.Fatalf("expected Go dependency version, got %#v", dependency["version"])
	}
}

func setFakeNPMOnPath(t *testing.T, npmJSON string) {
	t.Helper()
	t.Setenv("BOMLY_FAKE_NPM_MODE", "")
	t.Setenv("BOMLY_FAKE_NPM_JSON", npmJSON)
	prependPath(t, testHelperBinDir)
}

func setFakeMavenOnPath(t *testing.T, mavenTGF string) {
	t.Helper()
	binDir := t.TempDir()
	writeFakeMavenScript(t, binDir, "mvn", mavenTGF)
	separator := string(os.PathListSeparator)
	pathEnv := binDir
	if existing := os.Getenv("PATH"); existing != "" {
		pathEnv += separator + existing
	}
	t.Setenv("PATH", pathEnv)
}

func writeFakeMavenWrapper(t *testing.T, projectDir, mavenTGF string) {
	t.Helper()
	writeFakeMavenScript(t, projectDir, "mvnw", mavenTGF)
}

func setFakeGradleOnPath(t *testing.T, gradleOutput string) {
	t.Helper()
	t.Setenv("BOMLY_FAKE_GRADLE_FAIL", "")
	t.Setenv("BOMLY_FAKE_GRADLE_OUTPUT", gradleOutput)
	t.Setenv("BOMLY_FAKE_GRADLE_OUTPUT_FILE", "")
	prependPath(t, testHelperBinDir)
}

func setFailingFakeGradleOnPath(t *testing.T) {
	t.Helper()
	t.Setenv("BOMLY_FAKE_GRADLE_FAIL", "1")
	t.Setenv("BOMLY_FAKE_GRADLE_OUTPUT", "")
	t.Setenv("BOMLY_FAKE_GRADLE_OUTPUT_FILE", "")
	prependPath(t, testHelperBinDir)
}

func writeFakeGradleWrapper(t *testing.T, projectDir, gradleOutput string) {
	t.Helper()
	outputFile := filepath.Join(projectDir, "gradle-dependencies.txt")
	if err := os.WriteFile(outputFile, []byte(gradleOutput), 0o644); err != nil {
		t.Fatalf("write fake gradle output: %v", err)
	}

	if runtime.GOOS == "windows" {
		wrapperPath := filepath.Join(projectDir, "gradlew.bat")
		wrapper := []byte(fmt.Sprintf("@echo off\r\nset BOMLY_FAKE_GRADLE_FAIL=\r\nset BOMLY_FAKE_GRADLE_OUTPUT=\r\nset BOMLY_FAKE_GRADLE_OUTPUT_FILE=%s\r\n\"%s\" %%*\r\n", outputFile, fakeGradleBinPath))
		if err := os.WriteFile(wrapperPath, wrapper, 0o755); err != nil {
			t.Fatalf("write gradlew.bat: %v", err)
		}
		return
	}

	wrapperPath := filepath.Join(projectDir, "gradlew")
	wrapper := []byte(fmt.Sprintf("#!/bin/sh\nexport BOMLY_FAKE_GRADLE_FAIL=\nexport BOMLY_FAKE_GRADLE_OUTPUT=\nexport BOMLY_FAKE_GRADLE_OUTPUT_FILE=%s\nexec %s \"$@\"\n", shellQuote(outputFile), shellQuote(fakeGradleBinPath)))
	if err := os.WriteFile(wrapperPath, wrapper, 0o755); err != nil {
		t.Fatalf("write gradlew: %v", err)
	}
	if err := os.Chmod(wrapperPath, 0o755); err != nil {
		t.Fatalf("chmod gradlew: %v", err)
	}
}

func writeFakeMavenScript(t *testing.T, dir, baseName, mavenTGF string) {
	t.Helper()
	outputFile := filepath.Join(dir, baseName+"-tree.txt")
	if err := os.WriteFile(outputFile, []byte(mavenTGF), 0o644); err != nil {
		t.Fatalf("write fake maven output: %v", err)
	}

	scriptPath := filepath.Join(dir, baseName)
	if runtime.GOOS == "windows" {
		scriptPath += ".cmd"
	}

	var script string
	if runtime.GOOS == "windows" {
		script = fmt.Sprintf("@echo off\r\ntype %q\r\n", outputFile)
	} else {
		script = fmt.Sprintf("#!/bin/sh\ncat %q\n", outputFile)
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake maven script: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(scriptPath, 0o755); err != nil {
			t.Fatalf("chmod fake maven script: %v", err)
		}
	}
}

func setDynamicFakeNPMOnPath(t *testing.T) {
	t.Helper()
	t.Setenv("BOMLY_FAKE_NPM_MODE", "dynamic")
	t.Setenv("BOMLY_FAKE_NPM_JSON", "")
	prependPath(t, testHelperBinDir)
}

func setFakeGoOnPath(t *testing.T, listOutput string) {
	t.Helper()
	t.Setenv("BOMLY_FAKE_GO_LIST_OUTPUT", listOutput)
	prependPath(t, testHelperBinDir)
}

func prependPath(t *testing.T, dir string) {
	t.Helper()
	separator := string(os.PathListSeparator)
	pathEnv := dir
	if existing := os.Getenv("PATH"); existing != "" {
		pathEnv += separator + existing
	}
	t.Setenv("PATH", pathEnv)
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is required for this test: %v", err)
	}
}

func createGitNPMRepoHistory(t *testing.T) (string, string, string) {
	t.Helper()
	repoDir := t.TempDir()
	runGit(t, repoDir, "init", "--initial-branch=main")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Bomly Test")

	writeGitFixturePackageJSON(t, repoDir, `{
	  "name": "demo-app",
	  "version": "1.0.0",
	  "dependencies": {
	    "react": "18.2.0"
	  }
	}
`)
	runGit(t, repoDir, "add", "package.json")
	runGit(t, repoDir, "commit", "-m", "base")
	baseSHA := runGit(t, repoDir, "rev-parse", "HEAD")

	writeGitFixturePackageJSON(t, repoDir, `{
	  "name": "demo-app",
	  "version": "1.0.0",
	  "dependencies": {
	    "react": "19.0.0",
	    "zod": "3.23.0"
	  }
	}
`)
	runGit(t, repoDir, "add", "package.json")
	runGit(t, repoDir, "commit", "-m", "head")
	headSHA := runGit(t, repoDir, "rev-parse", "HEAD")
	return repoDir, baseSHA, headSHA
}

func writeGitFixturePackageJSON(t *testing.T, repoDir, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func scanPayloadPackages(payload map[string]any) ([]any, bool) {
	manifests, ok := payload["manifests"].([]any)
	if !ok {
		return nil, false
	}
	packages := make([]any, 0)
	for _, raw := range manifests {
		manifest, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		manifestPackages, ok := manifest["packages"].([]any)
		if !ok {
			continue
		}
		packages = append(packages, manifestPackages...)
	}
	return packages, true
}

func containsPackageWithScope(packages []any, targetName, targetScope string) bool {
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if pkg["name"] == targetName && pkg["scope"] == targetScope {
			return true
		}
	}
	return false
}

func containsPackageName(packages []any, targetName string) bool {
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if pkg["name"] == targetName {
			return true
		}
	}
	return false
}

func containsPackageDependency(packages []any, targetName, dependencyID string) bool {
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok || pkg["name"] != targetName {
			continue
		}
		dependencies, ok := pkg["dependencies"].([]any)
		if !ok {
			return false
		}
		for _, dep := range dependencies {
			if value, ok := dep.(string); ok && value == dependencyID {
				return true
			}
		}
	}
	return false
}

func containsPackageDependencies(packages []any, targetName string, expected []string) bool {
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok || pkg["name"] != targetName {
			continue
		}
		dependencies, ok := pkg["dependencies"].([]any)
		if !ok {
			return false
		}
		if len(dependencies) != len(expected) {
			return false
		}
		for idx, want := range expected {
			value, ok := dependencies[idx].(string)
			if !ok || value != want {
				return false
			}
		}
		return true
	}
	return false
}

func containsManifestPackageChange(manifests []any, status, targetName, targetVersion, section string) bool {
	for _, raw := range manifests {
		manifest, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if manifest["status"] != status {
			continue
		}
		values, ok := manifest[section].([]any)
		if !ok {
			continue
		}
		for _, changeRaw := range values {
			change, ok := changeRaw.(map[string]any)
			if !ok {
				continue
			}
			pkg, ok := change["package"].(map[string]any)
			if !ok {
				continue
			}
			if pkg["name"] == targetName && pkg["version"] == targetVersion {
				return true
			}
		}
	}
	return false
}

func containsManifestUpdatedPackageChange(manifests []any, status, targetName, targetVersion, previousVersion string) bool {
	for _, raw := range manifests {
		manifest, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if manifest["status"] != status {
			continue
		}
		values, ok := manifest["changed"].([]any)
		if !ok {
			continue
		}
		for _, changeRaw := range values {
			change, ok := changeRaw.(map[string]any)
			if !ok {
				continue
			}
			after, ok := change["after"].(map[string]any)
			if !ok {
				continue
			}
			before, ok := change["before"].(map[string]any)
			if !ok {
				continue
			}
			if after["name"] == targetName && after["version"] == targetVersion && before["version"] == previousVersion {
				return true
			}
		}
	}
	return false
}
