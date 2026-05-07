// Package scan exposes the command-facing scan pipeline API.
package scan

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/engine"
)

// Request defines input for a full scan pipeline run.
type Request = engine.PipelineRequest

// Result contains the full output of a scan pipeline run.
type Result = engine.PipelineResult

// Run executes the full scan pipeline and returns a consolidated result.
func Run(ctx context.Context, pipeline *engine.Pipeline, req Request) (Result, error) {
	if pipeline == nil {
		return Result{}, fmt.Errorf("scan pipeline is nil")
	}
	return pipeline.Run(ctx, req)
}
