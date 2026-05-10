//go:build qa

package qa_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/test/qa"
)

var (
	qaManifest = flag.String("manifest", "", "path to scan_targets.json")
	qaRunDir   = flag.String("run-dir", "", "QA artifact output directory")
	qaBomly    = flag.String("bomly", "", "bomly binary path")
	qaCase     = flag.String("case", "", "comma-separated QA case names to run; omitted runs all QA cases")
)

func TestDependencyGraphQA(t *testing.T) {
	repoRoot := repoRoot(t)
	manifest := envOrDefault("BOMLY_QA_TARGETS", *qaManifest)
	if strings.TrimSpace(manifest) == "" {
		manifest = qa.DefaultTargetsPath(repoRoot)
	}
	runDir := envOrDefault("BOMLY_QA_RUN_DIR", *qaRunDir)
	if strings.TrimSpace(runDir) == "" {
		runDir = filepath.Join(repoRoot, ".qa-runs", "latest")
	}
	bomlyPath := envOrDefault("BOMLY_BIN", *qaBomly)
	if strings.TrimSpace(bomlyPath) == "" {
		bomlyPath = filepath.Join(repoRoot, "bin", "bomly"+exeSuffix())
	}

	err := qa.Run(context.Background(), qa.RunOptions{
		ManifestPath:  manifest,
		RunDir:        runDir,
		BomlyPath:     bomlyPath,
		SelectedCases: qa.ParseCaseNames(*qaCase),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
