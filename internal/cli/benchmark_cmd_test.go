package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
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
	previousRun := runBenchmark
	runBenchmark = func(_ context.Context, opts benchmark.RunOptions) (benchmark.RunSummary, error) {
		if strings.Join(opts.SelectedSources, ",") != "github,syft" {
			t.Fatalf("sources = %#v", opts.SelectedSources)
		}
		if strings.Join(opts.SelectedEcosystems, ",") != "npm" {
			t.Fatalf("ecosystems = %#v", opts.SelectedEcosystems)
		}
		if opts.NativeScan == nil {
			t.Fatal("native scanner is nil")
		}
		return benchmark.RunSummary{SchemaVersion: "bomly.benchmark.v1", Status: "completed", RunDir: opts.RunDir}, nil
	}
	t.Cleanup(func() {
		runBenchmark = previousRun
	})

	cmd := newBenchmarkCmd()
	cmd.SetContext(opts.ToContext(context.Background(), opts.NewOptions()))
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

func TestBenchmarkCommandUsesStandardNotificationAndLoggingConventions(t *testing.T) {
	previousRun := runBenchmark
	runBenchmark = func(_ context.Context, opts benchmark.RunOptions) (benchmark.RunSummary, error) {
		_, _ = fmt.Fprintln(opts.Notifications, "plain progress")
		opts.Logger.Info("structured progress")
		return benchmark.RunSummary{SchemaVersion: "bomly.benchmark.v1", Status: "completed", RunDir: opts.RunDir}, nil
	}
	t.Cleanup(func() { runBenchmark = previousRun })

	tests := []struct {
		name         string
		args         []string
		wantStderr   string
		absentStderr string
	}{
		{name: "default notifications", args: []string{"benchmark"}, wantStderr: "plain progress", absentStderr: "structured progress"},
		{name: "verbose logger", args: []string{"benchmark", "-v"}, wantStderr: "structured progress", absentStderr: "plain progress"},
		{name: "quiet", args: []string{"benchmark", "--quiet"}, absentStderr: "progress"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, err := newRootCmd("test")
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs(test.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if test.wantStderr != "" && !strings.Contains(stderr.String(), test.wantStderr) {
				t.Fatalf("stderr missing %q:\n%s", test.wantStderr, stderr.String())
			}
			if test.absentStderr != "" && strings.Contains(stderr.String(), test.absentStderr) {
				t.Fatalf("stderr unexpectedly contains %q:\n%s", test.absentStderr, stderr.String())
			}
		})
	}
}

func TestBenchmarkCommandRejectsQuietWithVerbose(t *testing.T) {
	root, err := newRootCmd("test")
	if err != nil {
		t.Fatal(err)
	}
	root.SetArgs([]string{"benchmark", "--quiet", "-v"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--quiet cannot be combined with --verbose") {
		t.Fatalf("error = %v", err)
	}
}
