package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
)

func TestPipelineFailureSeparatesImpossibleSelectionsFromResolutionFailures(t *testing.T) {
	preflight := &engine.PreflightError{Issues: []engine.PreflightIssue{{Component: "reach", Requirement: "source-tree-v1"}}}
	if got, want := exit.Code(pipelineFailure(fmt.Errorf("base pipeline: %w", preflight))), exit.Code(exit.InvalidInputError("x")); got != want {
		t.Fatalf("a selection the plan cannot run exits %d, want the invalid-input code %d", got, want)
	}
	if got, want := exit.Code(pipelineFailure(errors.New("dependency resolution: boom"))), exit.Code(exit.ResolutionFailureError(errors.New("x"))); got != want {
		t.Fatalf("a resolution failure exits %d, want %d", got, want)
	}
}
