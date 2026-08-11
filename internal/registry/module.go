package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// embeddedHostContext implements sdk.HostContext for components registered
// in-process. It hands components the registry's logger, shared HTTP client
// provider, and the same kind-scoped configuration block a managed plugin
// would receive.
type embeddedHostContext struct {
	registry *Registry
	kind     sdk.PluginKind
	name     string
}

func (c *embeddedHostContext) Logger() *zap.Logger {
	if c == nil || c.registry == nil || c.registry.logger == nil {
		return zap.NewNop()
	}
	return c.registry.logger
}

func (c *embeddedHostContext) HTTPClient() *sdk.HTTPClientProvider {
	if c == nil || c.registry == nil {
		return nil
	}
	return c.registry.httpClientProvider()
}

func (c *embeddedHostContext) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded}
}

func (c *embeddedHostContext) DecodeConfig(v any) error {
	if c == nil || c.registry == nil {
		return nil
	}
	block := c.registry.ComponentConfig(c.kind, c.name)
	if len(block) == 0 {
		return nil
	}
	if v == nil {
		return fmt.Errorf("component config target is nil")
	}
	data, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("encode component config: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode component config: %w", err)
	}
	return nil
}

// RegisterModule validates an execution-neutral module, constructs its
// component with an embedded HostContext, and registers it with the supplied
// component options. It is the registration path composition entries use.
func (r *Registry) RegisterModule(m sdk.Module, opts ComponentOptions) error {
	if r == nil {
		return fmt.Errorf("register module: registry is nil")
	}
	if err := sdk.ValidateModule(m); err != nil {
		return fmt.Errorf("register module: %w", err)
	}
	ctx := context.Background()
	switch m.Kind {
	case sdk.PluginKindDetector:
		host := &embeddedHostContext{registry: r, kind: m.Kind, name: m.Detector.Descriptor.Name}
		detector, err := m.Detector.New(ctx, host)
		if err != nil {
			return fmt.Errorf("construct detector %q: %w", m.Detector.Descriptor.Name, err)
		}
		r.RegisterDetectorWithOptions(detector, opts)
	case sdk.PluginKindMatcher:
		host := &embeddedHostContext{registry: r, kind: m.Kind, name: m.Matcher.Descriptor.Name}
		matcher, err := m.Matcher.New(ctx, host)
		if err != nil {
			return fmt.Errorf("construct matcher %q: %w", m.Matcher.Descriptor.Name, err)
		}
		r.RegisterMatcherWithOptions(matcher, opts)
	case sdk.PluginKindAuditor:
		host := &embeddedHostContext{registry: r, kind: m.Kind, name: m.Auditor.Descriptor.Name}
		auditor, err := m.Auditor.New(ctx, host)
		if err != nil {
			return fmt.Errorf("construct auditor %q: %w", m.Auditor.Descriptor.Name, err)
		}
		r.RegisterAuditorWithOptions(auditor, opts)
	case sdk.PluginKindAnalyzer:
		host := &embeddedHostContext{registry: r, kind: m.Kind, name: m.Analyzer.Descriptor.Name}
		analyzer, err := m.Analyzer.New(ctx, host)
		if err != nil {
			return fmt.Errorf("construct analyzer %q: %w", m.Analyzer.Descriptor.Name, err)
		}
		r.RegisterAnalyzerWithOptions(analyzer, opts)
	default:
		return fmt.Errorf("register module: unsupported kind %q", m.Kind)
	}
	return nil
}
