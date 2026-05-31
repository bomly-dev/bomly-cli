package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/benchmark"
	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/spf13/cobra"
)

var benchmarkExecutable = os.Executable
var runBenchmark = benchmark.Run

func newBenchmarkCmd() *cobra.Command {
	var sources []string
	var ecosystems []string
	var cases []string
	var repository string
	var manifest string
	var runDir string
	var installFirst bool
	format := "text"

	cmd := &cobra.Command{
		Use:    "benchmark",
		Short:  "Run the local dependency-graph benchmark",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToLower(strings.TrimSpace(format)) {
			case "text", "json":
			default:
				return exit.InvalidInputError("unsupported benchmark format %q (accepted: text, json)", format)
			}
			binaryPath, err := benchmarkExecutable()
			if err != nil {
				return fmt.Errorf("resolve benchmark executable: %w", err)
			}
			if strings.TrimSpace(runDir) == "" {
				runDir = filepath.Join(".benchmark-runs", "latest")
			}
			summary, err := runBenchmark(cmd.Context(), benchmark.RunOptions{
				ManifestPath:       manifest,
				RunDir:             runDir,
				BinaryPath:         binaryPath,
				SelectedCases:      benchmark.ParseNames(cases...),
				SelectedSources:    benchmark.ParseNames(sources...),
				SelectedEcosystems: benchmark.ParseNames(ecosystems...),
				CustomRepository:   repository,
				InstallFirst:       installFirst,
				Progress:           cmd.ErrOrStderr(),
			})
			if renderErr := writeBenchmarkSummary(cmd, format, summary); renderErr != nil {
				return renderErr
			}
			return err
		},
	}
	cmd.Flags().StringSliceVar(&sources, "source", nil, "Baseline source(s): github, syft, syft-cyclonedx")
	cmd.Flags().StringSliceVar(&ecosystems, "ecosystem", nil, "Ecosystem(s) to benchmark; --repo requires exactly one")
	cmd.Flags().StringSliceVar(&cases, "case", nil, "Preset benchmark case(s) to run")
	cmd.Flags().StringVar(&repository, "repo", "", "Custom public https://github.com/<owner>/<repo> repository")
	cmd.Flags().StringVar(&manifest, "manifest", "", "Advanced benchmark target manifest override")
	cmd.Flags().StringVar(&runDir, "run-dir", "", "Benchmark artifact output directory")
	cmd.Flags().BoolVar(&installFirst, "install-first", false, "Run detector-specific dependency installation for a custom repository")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text or json")
	opts.BindJSONFormatFlag(cmd.Flags(), &format, "Shortcut for --format json")
	return cmd
}

func writeBenchmarkSummary(cmd *cobra.Command, format string, summary benchmark.RunSummary) error {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	}
	return benchmark.RenderText(cmd.OutOrStdout(), summary)
}
