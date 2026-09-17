package plugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

func TestTestReportsReadyState(t *testing.T) {
	root := t.TempDir()
	id := "acme.detector.ready"
	installDetectorPluginForHealthTests(t, root, id, true)

	result, err := Test(context.Background(), root, id, nil)
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if !result.Ready {
		t.Fatalf("expected plugin to be ready")
	}
	if result.Probe == "" {
		t.Fatalf("expected probe label in test result")
	}
}

func TestTestReportsNotReadyState(t *testing.T) {
	root := t.TempDir()
	id := "acme.detector.not-ready"
	installDetectorPluginForHealthTests(t, root, id, false)

	result, err := Test(context.Background(), root, id, nil)
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if result.Ready {
		t.Fatalf("expected plugin to be reported as not ready")
	}
}

func TestDoctorRunsVerifyAndTest(t *testing.T) {
	root := t.TempDir()
	id := "acme.detector.doctor"
	installDetectorPluginForHealthTests(t, root, id, true)

	result, err := Doctor(context.Background(), root, id, nil)
	if err != nil {
		t.Fatalf("Doctor() error = %v", err)
	}
	if len(result.Checks) == 0 {
		t.Fatalf("expected doctor result to include verify checks")
	}
	if !result.Ready || !result.Healthy {
		t.Fatalf("expected doctor result to be healthy, got ready=%v healthy=%v", result.Ready, result.Healthy)
	}
}

func installDetectorPluginForHealthTests(t *testing.T, root, id string, ready bool) {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), pluginTestExecutableName("bomly-plugin-fake-health"))
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSourceWithReady(id, ready)); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	if _, err := Install(context.Background(), root, binaryPath, InstallOptions{DevBinary: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
}

func fakeDetectorPluginSourceWithReady(id string, ready bool) string {
	readyValue := "false"
	if ready {
		readyValue = "true"
	}
	return `package main

import (
	"context"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type detector struct{}

func (d *detector) Descriptor(context.Context) (*plugin.DetectorDescriptor, error) {
	return &plugin.DetectorDescriptor{
		Name:           "` + id + `",
		Tags:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]plugin.PackageManagerSupport, error) {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *plugin.DetectRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: ` + readyValue + `}, nil
}

func (d *detector) Applicable(context.Context, *plugin.DetectRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(context.Context, *plugin.DetectRequest) (*plugin.DetectResponse, error) {
	return &plugin.DetectResponse{}, nil
}

func main() {
	runtime.ServeDetector(&detector{})
}
`
}

func pluginTestExecutableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
