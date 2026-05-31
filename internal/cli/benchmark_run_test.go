package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestBenchmarkNativeScannerUsesBomlyNativeDetector(t *testing.T) {
	projectDir := t.TempDir()
	lockfile := []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "benchmark": "1.0.0"
      }
    },
    "node_modules/benchmark": {
      "version": "1.0.0"
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), lockfile, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := benchmarkNativeScanner(zap.NewNop(), io.Discard, false)(context.Background(), benchmark.NativeScanRequest{
		CheckoutDir: projectDir,
		Repository:  "https://github.com/acme/demo",
		Revision:    "abc123",
		Ecosystem:   sdk.EcosystemNPM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Graph == nil || result.Graph.Size() == 0 {
		t.Fatalf("graph = %#v", result.Graph)
	}
	if !benchmarkContainsString(result.Detectors, detectors.NameNPM) {
		t.Fatalf("detectors = %#v, want %q", result.Detectors, detectors.NameNPM)
	}
	for _, detector := range result.Detectors {
		if strings.Contains(detector, "syft") {
			t.Fatalf("detectors = %#v, want native-only scan", result.Detectors)
		}
	}
}

func benchmarkContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
