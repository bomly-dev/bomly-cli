package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/baseline"
	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	scanengine "github.com/bomly-dev/bomly-cli/internal/engine/scan"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
)

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage portable package finding suppressions",
	}
	cmd.AddCommand(
		newBaselineWriteCmd("create"),
		newBaselineWriteCmd("update"),
		newBaselineWriteCmd("prune"),
		newBaselineInspectCmd(),
	)
	return cmd
}

func newBaselineWriteCmd(action string) *cobra.Command {
	description := baselineActionDescription(action)
	return &cobra.Command{
		Use:   action,
		Short: description,
		Long:  description + ".\n\nUse --analyze when the audited CI workflow also uses reachability analysis.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			configured := options.GetConfig()
			if err := validateBaselineMutationTarget(configured); err != nil {
				return err
			}
			if !configured.Enrich {
				return exit.InvalidInputError("baseline %s requires --enrich", action)
			}
			selection := configured.Baseline
			configured.Audit = true
			configured.Baseline = "none"
			options.SetConfig(configured)

			logger := commandLogger(cmd, "baseline")
			commandCtx, err := options.Prepare(cmd.Context(), logger)
			if err != nil {
				return err
			}
			defer func() { _ = commandCtx.Close() }()
			path, _, ok, err := baseline.ResolvePath(selection, commandCtx.ExecutionTarget())
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if !ok {
				return exit.InvalidInputError("baseline %s requires a local filesystem target and baseline path", action)
			}

			pipeline := engine.NewPipeline(commandCtx.Registry(), logger)
			request := commandCtx.PipelineRequest(sdk.ScopeUnknown, cmd.ErrOrStderr())
			result, err := scanengine.Run(cmd.Context(), pipeline, request)
			if err != nil {
				return exit.ResolutionFailureError(err)
			}
			if warningCount := baselineMutationWarningCount(result); warningCount > 0 {
				return exit.ResolutionFailureError(fmt.Errorf("baseline %s refused because the audit completed with %d degraded-coverage warning(s)", action, warningCount))
			}

			var document baseline.Document
			switch action {
			case "create":
				document = baseline.NewDocument(result.Findings, result.Registry)
				err = baseline.WriteAtomic(path, document, false)
			case "update", "prune":
				existing, loadErr := baseline.Load(path)
				if loadErr != nil {
					return exit.InvalidInputError("%v", loadErr)
				}
				if action == "update" {
					document = baseline.Update(existing, result.Findings, result.Registry)
				} else {
					document = baseline.Prune(existing, result.Findings, result.Registry)
				}
				err = baseline.WriteAtomic(path, document, true)
			}
			if err != nil {
				return fmt.Errorf("baseline %s: %w", action, err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s baseline %s (%d entries)\n", titleWord(action), path, len(document.Entries))
			return err
		},
	}
}

func validateBaselineMutationTarget(configured config.Resolved) error {
	if configured.URL != "" || configured.Image != "" || configured.SBOM {
		return exit.InvalidInputError("baseline lifecycle commands require a writable local project directory")
	}
	return nil
}

func baselineMutationWarningCount(result engine.PipelineResult) int {
	return len(result.DetectorWarnings) + len(result.MatchWarnings) + len(result.AnalyzeWarnings) + len(result.AuditWarnings)
}

func newBaselineInspectCmd() *cobra.Command {
	var jsonOutput bool
	var projectPath string
	cmd := &cobra.Command{
		Use:   "inspect [baseline]",
		Short: "Validate and display a finding baseline",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if strings.TrimSpace(projectPath) != "" {
				root = projectPath
			}
			path := filepath.Join(root, filepath.FromSlash(baseline.DefaultRelativePath))
			if len(args) == 1 {
				path = args[0]
				if !filepath.IsAbs(path) {
					path = filepath.Join(root, path)
				}
			}
			document, err := baseline.Load(path)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			if jsonOutput {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(document)
			}
			return renderBaselineDocument(cmd.OutOrStdout(), path, document)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Render the baseline as JSON")
	cmd.Flags().StringVar(&projectPath, "path", "", "Project directory used to resolve the default or a relative baseline path")
	return cmd
}

func renderBaselineDocument(w io.Writer, path string, document baseline.Document) error {
	if _, err := fmt.Fprintf(w, "Baseline: %s\nSchema: %s\nEntries: %d\n", path, document.SchemaVersion, len(document.Entries)); err != nil {
		return err
	}
	for _, entry := range document.Entries {
		identifier := entry.RuleID
		if len(entry.AdvisoryIDs) > 0 {
			identifier = strings.Join(entry.AdvisoryIDs, ", ")
		}
		if _, err := fmt.Fprintf(w, "- %s | %s | %s\n", entry.PackageRef, entry.Kind, identifier); err != nil {
			return err
		}
	}
	return nil
}

func baselineActionDescription(action string) string {
	switch action {
	case "create":
		return "Create a package finding baseline from the current project"
	case "update":
		return "Accept current findings into an existing baseline"
	default:
		return "Remove baseline entries absent from a complete current scan"
	}
}

func titleWord(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
