// Package hooks defines the pre-resolve and post-resolve hook contract used by the scan pipeline.
// Hook implementations come from the registry; this package only owns the interfaces, the
// per-hook context shapes, and the executor used to run a slice of hooks in priority order.
package hooks

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Descriptor describes a hook registration.
type Descriptor struct {
	Name     string
	Priority int
	Stage    string // "pre-resolve" | "post-resolve"
}

// PreResolveContext provides inputs available before detection.
type PreResolveContext struct {
	ExecutionTarget sdk.ExecutionTarget
	Subprojects     []sdk.Subproject
	ProjectPath     string
	Stderr          io.Writer
}

// PostResolveContext provides inputs available after full resolution.
type PostResolveContext struct {
	Consolidated sdk.ConsolidatedGraph
	Findings     []sdk.Finding
	ProjectPath  string
	Stderr       io.Writer
}

// PreResolveHook runs logic before detection.
type PreResolveHook interface {
	Descriptor() Descriptor
	Execute(context.Context, PreResolveContext) error
}

// PostResolveHook runs logic after all resolutions and auditing.
type PostResolveHook interface {
	Descriptor() Descriptor
	Execute(context.Context, PostResolveContext) error
}

// RunPre runs each pre-resolve hook in order. The first failure stops the chain.
func RunPre(ctx context.Context, logger *zap.Logger, hooks []PreResolveHook, hookCtx PreResolveContext) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	for _, hook := range hooks {
		desc := hook.Descriptor()
		logger.Debug("pipeline: running pre-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, hookCtx); err != nil {
			return fmt.Errorf("hook %s: %w", desc.Name, err)
		}
	}
	return nil
}

// RunPost runs each post-resolve hook in order, collecting errors so one failing hook
// does not prevent the rest from running.
func RunPost(ctx context.Context, logger *zap.Logger, hooks []PostResolveHook, hookCtx PostResolveContext) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	var errs []error
	for _, hook := range hooks {
		desc := hook.Descriptor()
		logger.Debug("pipeline: running post-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, hookCtx); err != nil {
			errs = append(errs, fmt.Errorf("hook %s: %w", desc.Name, err))
		}
	}
	return errors.Join(errs...)
}
