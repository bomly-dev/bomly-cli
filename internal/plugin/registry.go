package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-sdk"
)

// readyResponseError translates a plugin readiness response into the in-process
// readiness contract: nil means ready, a non-nil error carries the reason.
func readyResponseError(resp *sdk.ReadyResponse, err error) error {
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("plugin returned no readiness response")
	}
	if resp.Ready {
		return nil
	}
	if reason := strings.TrimSpace(resp.Reason); reason != "" {
		return errors.New(reason)
	}
	return errors.New("plugin reported not ready")
}

type registryWriter interface {
	RegisterDetector(sdk.Detector)
	RegisterDetectorWithOptions(sdk.Detector, registry.ComponentOptions)
	RegisterMatcher(sdk.Matcher)
	RegisterMatcherWithOptions(sdk.Matcher, registry.ComponentOptions)
	RegisterAuditor(sdk.Auditor)
	RegisterAuditorWithOptions(sdk.Auditor, registry.ComponentOptions)
	RegisterAnalyzer(sdk.Analyzer)
	RegisterAnalyzerWithOptions(sdk.Analyzer, registry.ComponentOptions)
	RegisterDetectorDiscoveryPlan(string, registry.DetectorDiscoveryPlan)
}

// RegisterRuntimePlugins loads enabled external plugins into the scan registry.
func RegisterRuntimePlugins(ctx context.Context, reg registryWriter, root string) error {
	if reg == nil {
		return nil
	}
	if root == "" && strings.Contains(os.Args[0], ".test") {
		return nil
	}
	ctx = launchContext(ctx, nil)
	infos, err := LoadRuntimePlugins(root)
	if err != nil {
		return err
	}
	externalOptions := registry.ComponentOptions{DefaultEnabled: true, Origin: sdk.ExternalOrigin}
	for _, info := range infos {
		switch info.Kind {
		case sdk.PluginKindDetector:
			reg.RegisterDetectorWithOptions(newExternalDetector(info, ctx), externalOptions)
			if plan, ok := detectorDiscoveryPlan(info); ok {
				reg.RegisterDetectorDiscoveryPlan(info.ID, plan)
			}
		case sdk.PluginKindMatcher:
			reg.RegisterMatcherWithOptions(newExternalMatcher(info, ctx), externalOptions)
		case sdk.PluginKindAuditor:
			reg.RegisterAuditorWithOptions(newExternalAuditor(info, ctx), externalOptions)
		case sdk.PluginKindAnalyzer:
			reg.RegisterAnalyzerWithOptions(newExternalAnalyzer(info, ctx), externalOptions)
		}
	}
	return nil
}

// acquireClient returns a live plugin client plus a release function. When the
// launch options carry a ClientPool the pooled subprocess is reused and the
// release is a no-op; otherwise a one-shot subprocess is started and release
// terminates it.
func acquireClient(ctx context.Context, executable, pluginID string) (sdk.Client, func(), error) {
	if options, ok := LaunchOptionsFromContext(ctx); ok && options.Pool != nil {
		client, err := options.Pool.Acquire(ctx, executable, pluginID)
		if err != nil {
			return nil, func() {}, err
		}
		return client, func() {}, nil
	}
	client, err := startPlugin(ctx, executable, pluginID)
	if err != nil {
		return nil, func() {}, err
	}
	return client.Raw(), client.Close, nil
}

type externalDetector struct {
	info      Info
	launchCtx context.Context
}

func (d externalDetector) Descriptor() sdk.DetectorDescriptor {
	if d.info.DetectorDescriptor == nil {
		return sdk.DetectorDescriptor{}
	}
	return *cloneDetectorDescriptor(d.info.DetectorDescriptor)
}

func (d externalDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	if d.info.DetectorDescriptor == nil {
		return nil
	}
	return clonePackageManagerSupport(d.info.DetectorDescriptor.PackageManagerSupport)
}

func (d externalDetector) Ready(ctx context.Context, req sdk.DetectionRequest) error {
	ctx = launchContext(ctx, d.launchCtx)
	client, release, err := acquireClient(ctx, d.info.Entrypoint, d.info.ID)
	if err != nil {
		return err
	}
	defer release()
	resp, err := client.DetectorReady(ctx, &req)
	return readyResponseError(resp, err)
}

func (d externalDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	ctx = launchContext(ctx, d.launchCtx)
	client, release, err := acquireClient(ctx, d.info.Entrypoint, d.info.ID)
	if err != nil {
		return false, err
	}
	defer release()
	resp, err := client.DetectorApplicable(ctx, &req)
	if err != nil {
		return false, fmt.Errorf("run external detector applicable %s: %w", d.info.ID, err)
	}
	return resp != nil && resp.Applicable, nil
}

func (d externalDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	ctx = launchContext(ctx, d.launchCtx)
	client, release, err := acquireClient(ctx, d.info.Entrypoint, d.info.ID)
	if err != nil {
		return err
	}
	defer release()
	_, err = client.DetectorInstall(ctx, &req)
	if err != nil {
		return fmt.Errorf("run external detector install %s: %w", d.info.ID, err)
	}
	return nil
}

func (d externalDetector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	ctx = launchContext(ctx, d.launchCtx)
	client, release, err := acquireClient(ctx, d.info.Entrypoint, d.info.ID)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	defer release()
	resp, err := client.Detect(ctx, &req)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("run external detector %s: %w", d.info.ID, err)
	}
	if resp == nil {
		return sdk.DetectionResult{}, nil
	}
	return *resp, nil
}

func (d externalDetector) RemediationHints(ctx context.Context, req sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	if d.info.DetectorDescriptor == nil || len(d.info.DetectorDescriptor.RemediationCapabilities) == 0 {
		return sdk.RemediationHintResponse{}, nil
	}
	ctx = launchContext(ctx, d.launchCtx)
	client, release, err := acquireClient(ctx, d.info.Entrypoint, d.info.ID)
	if err != nil {
		return sdk.RemediationHintResponse{}, fmt.Errorf("start external detector remediation hints %s: %w", d.info.ID, err)
	}
	defer release()
	resp, err := client.DetectorRemediationHints(ctx, &req)
	if err != nil {
		return sdk.RemediationHintResponse{}, fmt.Errorf("run external detector remediation hints %s: %w", d.info.ID, err)
	}
	if resp == nil {
		return sdk.RemediationHintResponse{}, nil
	}
	return *resp, nil
}

func newExternalDetector(info Info, ctx context.Context) sdk.Detector {
	return externalDetector{info: info, launchCtx: launchContext(ctx, nil)}
}

type externalMatcher struct {
	info      Info
	launchCtx context.Context
}

func (m externalMatcher) Descriptor() sdk.MatcherDescriptor {
	if m.info.MatcherDescriptor == nil {
		return sdk.MatcherDescriptor{}
	}
	return *cloneMatcherDescriptor(m.info.MatcherDescriptor)
}

func (m externalMatcher) Ready(ctx context.Context, req sdk.MatchRequest) error {
	ctx = launchContext(ctx, m.launchCtx)
	client, release, err := acquireClient(ctx, m.info.Entrypoint, m.info.ID)
	if err != nil {
		return err
	}
	defer release()
	resp, err := client.MatcherReady(ctx, &req)
	return readyResponseError(resp, err)
}

func (m externalMatcher) Applicable(ctx context.Context, req sdk.MatchRequest) (bool, error) {
	ctx = launchContext(ctx, m.launchCtx)
	client, release, err := acquireClient(ctx, m.info.Entrypoint, m.info.ID)
	if err != nil {
		return false, err
	}
	defer release()
	resp, err := client.MatcherApplicable(ctx, &req)
	return resp != nil && resp.Applicable, err
}

func (m externalMatcher) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	ctx = launchContext(ctx, m.launchCtx)
	client, release, err := acquireClient(ctx, m.info.Entrypoint, m.info.ID)
	if err != nil {
		return sdk.MatchResult{}, err
	}
	defer release()
	// The host understands MatchResult.PackageUpdates deltas, so advertise it.
	req.AcceptPackageUpdates = true
	resp, err := client.Match(ctx, &req)
	if err != nil {
		return sdk.MatchResult{}, fmt.Errorf("run external matcher %s: %w", m.info.ID, err)
	}
	if resp == nil {
		return sdk.MatchResult{Registry: req.Registry}, nil
	}
	result := *resp
	if result.Registry == nil {
		if len(result.PackageUpdates) > 0 {
			result.Registry = sdk.ApplyPackageUpdates(req.Registry, result.PackageUpdates)
		} else {
			result.Registry = req.Registry
		}
	}
	return result, nil
}

func newExternalMatcher(info Info, ctx context.Context) sdk.Matcher {
	return externalMatcher{info: info, launchCtx: launchContext(ctx, nil)}
}

type externalAuditor struct {
	info      Info
	launchCtx context.Context
}

func (a externalAuditor) Descriptor() sdk.AuditorDescriptor {
	if a.info.AuditorDescriptor == nil {
		return sdk.AuditorDescriptor{}
	}
	return *cloneAuditorDescriptor(a.info.AuditorDescriptor)
}

func (a externalAuditor) Ready(ctx context.Context, req sdk.AuditRequest) error {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return err
	}
	defer release()
	resp, err := client.AuditorReady(ctx, &req)
	return readyResponseError(resp, err)
}

func (a externalAuditor) Applicable(ctx context.Context, req sdk.AuditRequest) (bool, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return false, err
	}
	defer release()
	resp, err := client.AuditorApplicable(ctx, &req)
	return resp != nil && resp.Applicable, err
}

func (a externalAuditor) Audit(ctx context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return sdk.AuditResult{}, err
	}
	defer release()
	resp, err := client.Audit(ctx, &req)
	if err != nil {
		return sdk.AuditResult{}, fmt.Errorf("run external auditor %s: %w", a.info.ID, err)
	}
	if resp == nil {
		return sdk.AuditResult{}, nil
	}
	return *resp, nil
}

func newExternalAuditor(info Info, ctx context.Context) sdk.Auditor {
	return externalAuditor{info: info, launchCtx: launchContext(ctx, nil)}
}

type externalAnalyzer struct {
	info      Info
	launchCtx context.Context
}

func (a externalAnalyzer) Descriptor() sdk.AnalyzerDescriptor {
	if a.info.AnalyzerDescriptor == nil {
		return sdk.AnalyzerDescriptor{}
	}
	return *cloneAnalyzerDescriptor(a.info.AnalyzerDescriptor)
}

func (a externalAnalyzer) Ready(ctx context.Context, req sdk.AnalyzeRequest) error {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return err
	}
	defer release()
	resp, err := client.AnalyzerReady(ctx, &req)
	return readyResponseError(resp, err)
}

func (a externalAnalyzer) Applicable(ctx context.Context, req sdk.AnalyzeRequest) (bool, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return false, err
	}
	defer release()
	resp, err := client.AnalyzerApplicable(ctx, &req)
	return resp != nil && resp.Applicable, err
}

func (a externalAnalyzer) Analyze(ctx context.Context, req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, release, err := acquireClient(ctx, a.info.Entrypoint, a.info.ID)
	if err != nil {
		return sdk.AnalyzeResult{}, err
	}
	defer release()
	// The host understands AnalyzeResult.PackageUpdates deltas, so advertise it.
	req.AcceptPackageUpdates = true
	resp, err := client.Analyze(ctx, &req)
	if err != nil {
		return sdk.AnalyzeResult{}, fmt.Errorf("run external analyzer %s: %w", a.info.ID, err)
	}
	if resp == nil {
		return sdk.AnalyzeResult{Registry: req.Registry}, nil
	}
	result := *resp
	if result.Registry == nil {
		if len(result.PackageUpdates) > 0 {
			result.Registry = sdk.ApplyPackageUpdates(req.Registry, result.PackageUpdates)
		} else {
			result.Registry = req.Registry
		}
	}
	return result, nil
}

func newExternalAnalyzer(info Info, ctx context.Context) sdk.Analyzer {
	return externalAnalyzer{info: info, launchCtx: launchContext(ctx, nil)}
}

func launchContext(ctx context.Context, fallback context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := LaunchOptionsFromContext(ctx); ok {
		return ctx
	}
	if options, ok := LaunchOptionsFromContext(fallback); ok {
		return WithLaunchOptions(ctx, options)
	}
	return WithLaunchOptions(ctx, LaunchOptions{})
}
