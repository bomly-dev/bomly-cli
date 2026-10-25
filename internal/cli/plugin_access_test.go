package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

// enforcementClaims are phrasings that would present a publisher's
// declaration as a restriction Bomly applies.
var enforcementClaims = []string{"is limited to", "is restricted to", "sandbox", "only has access", "enforced by"}

func TestRenderAccessDisclosureLabelsTheClaimAsUnverified(t *testing.T) {
	var declared strings.Builder
	if err := renderAccessDisclosure(&declared, &plugin.Access{
		FilesystemRead: []plugin.FilesystemScope{plugin.FilesystemCache, plugin.FilesystemProject},
		Network:        []string{plugin.AccessAny, "api.osv.dev"},
		Environment:    []string{"GITHUB_TOKEN"},
	}); err != nil {
		t.Fatalf("renderAccessDisclosure() error = %v", err)
	}
	for _, want := range []string{
		"the publisher's claim; Bomly does not verify or enforce it",
		"Filesystem read  : cache, project",
		"Filesystem write : none declared",
		"Network          : any destination, api.osv.dev",
		"Environment      : GITHUB_TOKEN",
		"Subprocesses     : none declared",
	} {
		if !strings.Contains(declared.String(), want) {
			t.Errorf("declared disclosure is missing %q:\n%s", want, declared.String())
		}
	}

	var unknown strings.Builder
	if err := renderAccessDisclosure(&unknown, nil); err != nil {
		t.Fatalf("renderAccessDisclosure(nil) error = %v", err)
	}
	if !strings.Contains(unknown.String(), "Declared access: unknown") || !strings.Contains(unknown.String(), "can use everything your") {
		t.Fatalf("a manifest without an access block must read as unknown and unrestricted, got:\n%s", unknown.String())
	}
	for _, output := range []string{declared.String(), unknown.String()} {
		for _, claim := range enforcementClaims {
			if strings.Contains(strings.ToLower(output), claim) {
				t.Errorf("disclosure must never claim enforcement (%q):\n%s", claim, output)
			}
		}
	}
}

func TestRenderPluginInfoShowsDeclaredRequirements(t *testing.T) {
	info := managedplugin.Info{
		Manifest: managedplugin.Manifest{ID: "reach", Name: "reach", Kind: plugin.PluginKindAnalyzer, Version: "1.0.0", Runtime: "builtin"},
		AnalyzerDescriptor: &plugin.AnalyzerDescriptor{
			Name:     "reach",
			Requires: plugin.Requirements{plugin.RequirementVulnerabilityRecords, "future-input-v2", plugin.RequirementSourceTree},
		},
		BuiltIn: true,
	}
	var output strings.Builder
	if err := renderPluginInfo(&output, info); err != nil {
		t.Fatalf("renderPluginInfo() error = %v", err)
	}
	want := "Requires : future-input-v2 (unknown to this Bomly version), source-tree-v1, vulnerability-records-v1"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("renderPluginInfo() must list the declared requirements, sorted, got:\n%s", output.String())
	}
	if strings.Contains(output.String(), "Declared access") {
		t.Fatalf("a built-in component is part of Bomly and carries no publisher disclosure:\n%s", output.String())
	}
}

func TestPluginEnableShowsTheDisclosureBeforeEnabling(t *testing.T) {
	root := newPluginTestRoot(t)
	id := "acme.detector.cli.access"
	declareInstalledAccess(t, installCLIAccessDetectorPlugin(t, id), `{"network":["API.Example.com"],"subprocesses":["go"]}`)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "enable", id})
	if err := root.Execute(); err != nil {
		t.Fatalf("plugin enable error = %v", err)
	}
	text := output.String()
	assertInOrder(t, text, []string{"Declared access (the publisher's claim", "Network          : api.example.com", "enabled " + id})
}

func TestPluginJSONViewsExposeTheDisclosureState(t *testing.T) {
	root := newPluginTestRoot(t)
	legacy := "acme.detector.cli.legacy"
	declared := "acme.detector.cli.declared"
	installCLIAccessDetectorPlugin(t, legacy)
	declareInstalledAccess(t, installCLIAccessDetectorPlugin(t, declared), `{}`)

	var list strings.Builder
	root.SetOut(&list)
	root.SetArgs([]string{"plugin", "list", "--external", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("plugin list error = %v", err)
	}
	var response managedplugin.ListResponse
	if err := json.Unmarshal([]byte(list.String()), &response); err != nil {
		t.Fatalf("decode plugin list: %v\n%s", err, list.String())
	}
	states := map[string]managedplugin.AccessDisclosure{}
	for _, info := range response.Detectors {
		states[info.ID] = info.AccessDisclosure
		if info.ID == declared && (info.Access == nil || info.Access.Network != nil) {
			t.Fatalf("an empty access block is a claim of no access and must survive as one, got %+v", info.Access)
		}
	}
	if states[legacy] != managedplugin.AccessUnknown || states[declared] != managedplugin.AccessDeclared {
		t.Fatalf("plugin list --json disclosure states = %v", states)
	}

	for _, command := range []string{"verify", "doctor"} {
		var output strings.Builder
		// A fresh root over the same plugin store: newPluginTestRoot would
		// point HOME somewhere empty.
		root, err := newRootCmd("0.9.0-test")
		if err != nil {
			t.Fatalf("newRootCmd() error = %v", err)
		}
		root.SetOut(&output)
		root.SetArgs([]string{"plugin", command, declared, "--json"})
		if err := root.Execute(); err != nil {
			t.Fatalf("plugin %s error = %v", command, err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(output.String()), &result); err != nil {
			t.Fatalf("decode plugin %s: %v\n%s", command, err, output.String())
		}
		if result["accessDisclosure"] != string(managedplugin.AccessDeclared) || result["access"] == nil {
			t.Fatalf("plugin %s --json must carry the declared access, got %v", command, result)
		}
	}
}

// installCLIAccessDetectorPlugin dev-installs a fake detector into a plugin
// store private to the test, so no other test sees it.
func installCLIAccessDetectorPlugin(t *testing.T, id string) string {
	t.Helper()
	if os.Getenv(managedplugin.EnvPluginHome) == "" {
		t.Setenv(managedplugin.EnvPluginHome, t.TempDir())
	}
	binaryPath := filepath.Join(t.TempDir(), cliTestExecutableName("bomly-plugin-cli-access"))
	if err := testutil.BuildGoBinary(t, binaryPath, cliHealthDetectorPluginSource(id, true)); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	result, err := managedplugin.Install(context.Background(), "", binaryPath, managedplugin.InstallOptions{DevBinary: true})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	return result.Installed.Path
}

// declareInstalledAccess adds an access block to an installed plugin's
// manifest, as a published package would carry it.
func declareInstalledAccess(t *testing.T, dir, access string) {
	t.Helper()
	path := filepath.Join(dir, "bomly-plugin.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest["access"] = json.RawMessage(access)
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
