package scan

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

func (p *Pipeline) runPreHooks(ctx context.Context, req PipelineRequest) error {
	hooks := p.Registry.PreResolveHooks()
	for _, hook := range hooks {
		desc := hook.Descriptor()
		p.Logger.Debug("pipeline: running pre-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, PreResolveContext{
			ExecutionTarget: req.ExecutionTarget,
			Subprojects:     req.Subprojects,
			ProjectPath:     req.ProjectPath,
			Stderr:          req.Stderr,
		}); err != nil {
			return fmt.Errorf("hook %s: %w", desc.Name, err)
		}
	}
	return nil
}

func (p *Pipeline) runPostHooks(ctx context.Context, req PipelineRequest, result PipelineResult) error {
	hooks := p.Registry.PostResolveHooks()
	var errs []error
	for _, hook := range hooks {
		desc := hook.Descriptor()
		p.Logger.Debug("pipeline: running post-resolve hook", zap.String("name", desc.Name))
		if err := hook.Execute(ctx, PostResolveContext{
			Consolidated: result.Consolidated,
			Findings:     result.Findings,
			ProjectPath:  req.ProjectPath,
			Stderr:       req.Stderr,
		}); err != nil {
			errs = append(errs, fmt.Errorf("hook %s: %w", desc.Name, err))
		}
	}
	return errors.Join(errs...)
}
