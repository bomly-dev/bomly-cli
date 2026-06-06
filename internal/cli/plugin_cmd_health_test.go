package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func TestPluginTestReady(t *testing.T) {
	root := newPluginTestRoot(t)
	id := "acme.detector.cli.ready"
	installCLIHealthDetectorPlugin(t, id, true)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "test", id})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}
	if !strings.Contains(output.String(), "[ok]") || !strings.Contains(output.String(), "ready") {
		t.Fatalf("expected ready output, got:\n%s", output.String())
	}
}

func TestPluginTestNotReadyFails(t *testing.T) {
	root := newPluginTestRoot(t)
	id := "acme.detector.cli.not-ready"
	installCLIHealthDetectorPlugin(t, id, false)

	root.SetArgs([]string{"plugin", "test", id})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected plugin test to fail for not-ready plugin")
	}
	if code := exit.Code(err); code != 1 {
		t.Fatalf("expected exit code 1, got %d (err=%v)", code, err)
	}
}

func TestPluginTestUnknownPluginInvalidInput(t *testing.T) {
	root := newPluginTestRoot(t)
	root.SetArgs([]string{"plugin", "test", "missing.plugin"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected missing plugin to return an error")
	}
	if code := exit.Code(err); code != 4 {
		t.Fatalf("expected exit code 4, got %d (err=%v)", code, err)
	}
}

func TestPluginDoctorJSON(t *testing.T) {
	root := newPluginTestRoot(t)
	id := "acme.detector.cli.doctor"
	installCLIHealthDetectorPlugin(t, id, true)

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"plugin", "doctor", id, "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(output.String()), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput:\n%s", err, output.String())
	}
	if healthy, ok := result["healthy"].(bool); !ok || !healthy {
		t.Fatalf("expected healthy=true in doctor output, got %#v", result)
	}
	if ready, ok := result["ready"].(bool); !ok || !ready {
		t.Fatalf("expected ready=true in doctor output, got %#v", result)
	}
}

func installCLIHealthDetectorPlugin(t *testing.T, id string, ready bool) {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), cliTestExecutableName("bomly-plugin-cli-health"))
	if err := testutil.BuildGoBinary(t, binaryPath, cliHealthDetectorPluginSource(id, ready)); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	if _, err := managedplugin.Install(context.Background(), "", binaryPath, managedplugin.InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
}

func cliHealthDetectorPluginSource(id string, ready bool) string {
	readyValue := "false"
	if ready {
		readyValue = "true"
	}
	return `package main

import (
	"context"
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type detector struct{}

func (d *detector) Metadata(context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Kind:             schemav1.PluginKindDetector,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (d *detector) Descriptor(context.Context) (*schemav1.DetectorDescriptor, error) {
	return &schemav1.DetectorDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
		Tags:           []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]schemav1.PackageManagerSupport, error) {
	return []schemav1.PackageManagerSupport{schemav1.Support(schemav1.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *schemav1.DetectRequest) (*schemav1.ReadyResponse, error) {
	return &schemav1.ReadyResponse{Ready: ` + readyValue + `}, nil
}

func (d *detector) Applicable(context.Context, *schemav1.DetectRequest) (*schemav1.ApplicableResponse, error) {
	return &schemav1.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(context.Context, *schemav1.DetectRequest) (*schemav1.DetectResponse, error) {
	return &schemav1.DetectResponse{}, nil
}

func main() {
	schemav1.ServeDetector(&detector{})
}
`
}

func cliTestExecutableName(base string) string {
	if strings.HasSuffix(strings.ToLower(base), ".exe") {
		return base
	}
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
