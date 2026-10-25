package cli

import (
	"errors"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
)

// pipelineFailure maps a pipeline error to its exit code. A selection the
// plan can never run -- an explicitly selected component whose declared
// requirements the target cannot meet -- is invalid input; anything else
// failed while resolving.
func pipelineFailure(err error) error {
	if _, ok := errors.AsType[*engine.PreflightError](err); ok {
		return exit.InvalidInputError("%v", err)
	}
	return exit.ResolutionFailureError(err)
}
