package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
)

func TestBenchmarkCommandIsHiddenFromRootHelp(t *testing.T) {
	root, err := newRootCmd("test")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "benchmark") {
		t.Fatalf("root help exposed hidden benchmark:\n%s", out.String())
	}
	cmd, _, err := root.Find([]string{"benchmark"})
	if err != nil || cmd == nil {
		t.Fatalf("root.Find(benchmark) = %#v, %v", cmd, err)
	}
}

func TestBenchmarkCommandPassesFiltersAndRendersJSON(t *testing.T) {
	previousExecutable := benchmarkExecutable
	previousRun := runBenchmark
	benchmarkExecutable = func() (string, error) { return "bomly-test", nil }
	runBenchmark = func(_ context.Context, opts benchmark.RunOptions) (benchmark.RunSummary, error) {
		if strings.Join(opts.SelectedSources, ",") != "github,syft" {
			t.Fatalf("sources = %#v", opts.SelectedSources)
		}
		if strings.Join(opts.SelectedEcosystems, ",") != "npm" {
			t.Fatalf("ecosystems = %#v", opts.SelectedEcosystems)
		}
		return benchmark.RunSummary{SchemaVersion: "bomly.benchmark.v1", Status: "completed", RunDir: opts.RunDir}, nil
	}
	t.Cleanup(func() {
		benchmarkExecutable = previousExecutable
		runBenchmark = previousRun
	})

	cmd := newBenchmarkCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--source", "github,syft", "--ecosystem", "npm", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"status": "completed"`) {
		t.Fatalf("output = %s", out.String())
	}
}

func TestBenchmarkCommandDefinesLocalOnlyFlags(t *testing.T) {
	cmd := newBenchmarkCmd()
	for _, name := range []string{"source", "ecosystem", "case", "repo", "install-first", "manifest", "run-dir", "format", "json"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("benchmark command missing --%s", name)
		}
	}
}
