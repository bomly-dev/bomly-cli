package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func TestPluginList_TableSectionsAndDetectorColumns(t *testing.T) {
	root := newPluginTestRoot(t)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "list", "--all"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	text := output.String()
	for _, want := range []string{
		"Detectors:",
		"Matchers:",
		"Auditors:",
		"NAME",
		"TYPE",
		"PACKAGE MANAGERS",
		"ECOSYSTEMS",
		"npm-detector",
		"npm-native-detector",
		"* Complete plugin metadata",
		"--format json",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected plugin list output to contain %q, got:\n%s", want, text)
		}
	}

	for _, removed := range []string{"ID", "KIND", "SOURCE", "EXPECTED EVIDENCE", "VERSION"} {
		if strings.Contains(text, removed) {
			t.Fatalf("expected plugin list output to omit legacy column %q, got:\n%s", removed, text)
		}
	}

	detectorHeader := tableHeaderLine(t, render.StripANSI(text), "ECOSYSTEMS")
	assertInOrder(t, detectorHeader, []string{"ECOSYSTEMS", "PACKAGE MANAGERS", "NAME", "TYPE", "STATE"})
}

func TestPluginList_KindFilterMatchers(t *testing.T) {
	root := newPluginTestRoot(t)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "list", "--matchers"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	text := output.String()
	if !strings.Contains(text, "Matchers:") {
		t.Fatalf("expected matcher section in output, got:\n%s", text)
	}
	matcherHeader := tableHeaderLine(t, render.StripANSI(text), "NAME")
	assertInOrder(t, matcherHeader, []string{"NAME", "TYPE", "STATE"})
	for _, omitted := range []string{"ECOSYSTEMS", "PACKAGE MANAGERS", "VERSION"} {
		if strings.Contains(text, omitted) {
			t.Fatalf("expected matcher table to omit %q, got:\n%s", omitted, text)
		}
	}
	for _, omitted := range []string{"Detectors:", "Auditors:"} {
		if strings.Contains(text, omitted) {
			t.Fatalf("expected %q to be omitted, got:\n%s", omitted, text)
		}
	}
}

func TestPluginList_FormatJSON(t *testing.T) {
	root := newPluginTestRoot(t)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "list", "--detectors", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	var items []map[string]any
	if err := json.Unmarshal([]byte(output.String()), &items); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput:\n%s", err, output.String())
	}
	if len(items) == 0 {
		t.Fatal("expected non-empty detector plugin JSON output")
	}
	foundNPMDetector := false
	for _, item := range items {
		kind, _ := item["kind"].(string)
		if kind != string(plugschema.PluginKindDetector) {
			t.Fatalf("expected detector kind only, got %q in %#v", kind, item)
		}
		if item["id"] != "npm-detector" {
			continue
		}
		foundNPMDetector = true
		if version, _ := item["version"].(string); version == "" {
			t.Fatalf("expected npm detector JSON to include version, got %#v", item)
		}
		descriptor, ok := item["detectorDescriptor"].(map[string]any)
		if !ok {
			t.Fatalf("expected npm detector JSON to include detectorDescriptor, got %#v", item)
		}
		support, ok := descriptor["packageManagerSupport"].([]any)
		if !ok || len(support) == 0 {
			t.Fatalf("expected npm detector JSON to include packageManagerSupport, got %#v", descriptor)
		}
		firstSupport, ok := support[0].(map[string]any)
		if !ok {
			t.Fatalf("expected packageManagerSupport entry object, got %#v", support[0])
		}
		evidence, ok := firstSupport["evidencePatterns"].([]any)
		if !ok || len(evidence) == 0 {
			t.Fatalf("expected npm detector JSON to include evidencePatterns, got %#v", firstSupport)
		}
	}
	if !foundNPMDetector {
		t.Fatalf("expected detector JSON output to include npm-detector, got %#v", items)
	}
}

func TestPluginList_InvalidFormat(t *testing.T) {
	root := newPluginTestRoot(t)

	root.SetArgs([]string{"plugin", "list", "--format", "yaml"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected invalid format to return an error")
	}
	if !strings.Contains(err.Error(), `parse format: unsupported format "yaml"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestColorPluginType_HighlightsExternal(t *testing.T) {
	info := managedplugin.PluginInfo{BuiltIn: false}
	colored := colorPluginType("external", info)
	if colored == "external" {
		t.Fatal("expected external plugin type to be ANSI-colored")
	}
}

func TestSortPluginInfos_EnabledEcosystemThenID(t *testing.T) {
	items := []managedplugin.PluginInfo{
		{Manifest: managedplugin.Manifest{ID: "z-disabled", Kind: plugschema.PluginKindDetector}, Enabled: false},
		{
			Manifest: managedplugin.Manifest{
				ID:   "z-enabled-npm",
				Kind: plugschema.PluginKindDetector,
				DetectorDescriptor: &plugschema.DetectorDescriptor{
					SupportedEcosystems: []plugschema.Ecosystem{plugschema.EcosystemNPM},
				},
			},
			Enabled: true,
		},
		{Manifest: managedplugin.Manifest{ID: "b-enabled-matcher", Kind: plugschema.PluginKindMatcher}, Enabled: true},
		{
			Manifest: managedplugin.Manifest{
				ID:   "b-enabled-go",
				Kind: plugschema.PluginKindDetector,
				DetectorDescriptor: &plugschema.DetectorDescriptor{
					SupportedEcosystems: []plugschema.Ecosystem{plugschema.EcosystemGo},
				},
			},
			Enabled: true,
		},
	}

	sortPluginInfos(items)

	got := []string{items[0].ID, items[1].ID, items[2].ID, items[3].ID}
	want := []string{"b-enabled-go", "z-enabled-npm", "b-enabled-matcher", "z-disabled"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected sort order: got %v, want %v", got, want)
	}
}

func TestPluginList_DetectorSummariesAndSyftManagers(t *testing.T) {
	root := newPluginTestRoot(t)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "list", "--all", "--detectors"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	text := render.StripANSI(output.String())
	if strings.Contains(text, "package-lock.json") {
		t.Fatalf("expected detector table to omit expected evidence values, got:\n%s", text)
	}
	if strings.Contains(text, "(omitted)") {
		t.Fatalf("expected syft package managers to be summarized instead of omitted, got:\n%s", text)
	}
	if !strings.Contains(text, "syft-detector") || !strings.Contains(text, "+") || !strings.Contains(text, "more") {
		t.Fatalf("expected syft package managers to use +N summary format, got:\n%s", text)
	}
	if !strings.Contains(text, "* Complete plugin metadata") || !strings.Contains(text, "--format json") {
		t.Fatalf("expected table footnote to point to JSON details, got:\n%s", text)
	}
}

func TestPluginList_TableWrapsLongDetectorColumns(t *testing.T) {
	root := newPluginTestRoot(t)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "list", "--all", "--detectors"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	text := render.StripANSI(output.String())
	for _, line := range strings.Split(text, "\n") {
		if width := len([]rune(line)); width > 140 {
			t.Fatalf("expected wrapped detector table line <= 140 columns, got %d:\n%s", width, line)
		}
	}
}

func tableHeaderLine(t *testing.T, text string, contains string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, contains) {
			return line
		}
	}
	t.Fatalf("expected table header containing %q in output:\n%s", contains, text)
	return ""
}

func assertInOrder(t *testing.T, value string, parts []string) {
	t.Helper()
	last := -1
	for _, part := range parts {
		idx := strings.Index(value, part)
		if idx < 0 {
			t.Fatalf("expected %q to contain %q", value, part)
		}
		if idx <= last {
			t.Fatalf("expected %q to appear after previous columns in %q", part, value)
		}
		last = idx
	}
}

func newPluginTestRoot(t *testing.T) *cobra.Command {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}
	return root
}
