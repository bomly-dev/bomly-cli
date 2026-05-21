package plugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
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
	schemav1 "github.com/bomly-dev/bomly-cli/sdk"
)

type detector struct{}

func (d *detector) Metadata(context.Context) (*schemav1.PluginMetadata, error) {
	return &schemav1.PluginMetadata{
		ID:               "` + id + `",
		Name:             "Health Test Detector",
		Version:          "1.0.0",
		Kind:             schemav1.PluginKindDetector,
		PluginAPIVersion: schemav1.PluginAPIVersion,
	}, nil
}

func (d *detector) Descriptor(context.Context) (*schemav1.DetectorDescriptor, error) {
	return &schemav1.DetectorDescriptor{
		Name:           "` + id + `",
		Enabled:        true,
		Origin:         schemav1.ExternalOrigin,
		SupportedModes: []schemav1.TargetMode{schemav1.TargetModeFullGraph},
		Capabilities:   []string{"dependency-detection"},
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

func pluginTestExecutableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
