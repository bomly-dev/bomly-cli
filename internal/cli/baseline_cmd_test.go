package cli

import (
	"bytes"
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
