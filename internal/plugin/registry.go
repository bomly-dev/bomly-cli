package plugin

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	model "github.com/bomly-dev/bomly-cli/sdk"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

type registryWriter interface {
	RegisterDetector(model.Detector)
	RegisterMatcher(model.Matcher)
	RegisterAuditor(model.Auditor)
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
	for _, info := range infos {
		switch info.Kind {
		case plugschema.PluginKindDetector:
			reg.RegisterDetector(newExternalDetector(info, ctx))
			if plan, ok := detectorDiscoveryPlan(info.Manifest); ok {
				reg.RegisterDetectorDiscoveryPlan(info.ID, plan)
			}
		case plugschema.PluginKindMatcher:
			reg.RegisterMatcher(newExternalMatcher(info, ctx))
		case plugschema.PluginKindAuditor:
			reg.RegisterAuditor(newExternalAuditor(info, ctx))
		}
	}
	return nil
}

type externalDetector struct {
	info      PluginInfo
	launchCtx context.Context
}

func (d externalDetector) Metadata(context.Context) (*plugschema.PluginMetadata, error) {
	return metadataFromPluginInfo(d.info), nil
}

func (d externalDetector) Descriptor() model.DetectorDescriptor {
	if d.info.DetectorDescriptor == nil {
		return model.DetectorDescriptor{}
	}
	desc := *cloneDetectorDescriptor(d.info.DetectorDescriptor)
	desc.Origin = model.ExternalOrigin
	return desc
}

func (d externalDetector) PackageManagerSupport() []model.PackageManagerSupport {
	if d.info.Manifest.DetectorDescriptor == nil {
		return nil
	}
	return clonePackageManagerSupport(d.info.Manifest.DetectorDescriptor.PackageManagerSupport)
}

func (d externalDetector) Ready() bool {
	ctx := launchContext(context.Background(), d.launchCtx)
	client, err := startPlugin(ctx, d.info.Entrypoint)
	if err != nil {
		return false
	}
	defer client.Close()
	resp, err := client.Raw().DetectorReady(ctx, &model.DetectRequest{})
	if err != nil {
		return false
	}
	return resp != nil && resp.Ready
}

func (d externalDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	ctx = launchContext(ctx, d.launchCtx)
	client, err := startPlugin(ctx, d.info.Entrypoint)
	if err != nil {
		return false, err
	}
	defer client.Close()
	resp, err := client.Raw().DetectorApplicable(ctx, &req)
	if err != nil {
		return false, fmt.Errorf("run external detector applicable %s: %w", d.info.ID, err)
	}
	return resp != nil && resp.Applicable, nil
}

func (d externalDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	ctx = launchContext(ctx, d.launchCtx)
	client, err := startPlugin(ctx, d.info.Entrypoint)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.Raw().DetectorInstall(ctx, &req)
	if err != nil {
		return fmt.Errorf("run external detector install %s: %w", d.info.ID, err)
	}
	return nil
}

func (d externalDetector) ResolveGraph(ctx context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	ctx = launchContext(ctx, d.launchCtx)
	client, err := startPlugin(ctx, d.info.Entrypoint)
	if err != nil {
		return model.DetectionResult{}, err
	}
	defer client.Close()
	resp, err := client.Raw().Detect(ctx, &req)
	if err != nil {
		return model.DetectionResult{}, fmt.Errorf("run external detector %s: %w", d.info.ID, err)
	}
	if resp == nil {
		return model.DetectionResult{}, nil
	}
	return *resp, nil
}

func newExternalDetector(info PluginInfo, ctx context.Context) model.Detector {
	return externalDetector{info: info, launchCtx: launchContext(ctx, nil)}
}

type externalMatcher struct {
	info      PluginInfo
	launchCtx context.Context
}

func (m externalMatcher) Metadata(context.Context) (*plugschema.PluginMetadata, error) {
	return metadataFromPluginInfo(m.info), nil
}

func (m externalMatcher) Descriptor() model.MatcherDescriptor {
	if m.info.MatcherDescriptor == nil {
		return model.MatcherDescriptor{}
	}
	return *cloneMatcherDescriptor(m.info.MatcherDescriptor)
}

func (m externalMatcher) Ready() bool {
	ctx := launchContext(context.Background(), m.launchCtx)
	client, err := startPlugin(ctx, m.info.Entrypoint)
	if err != nil {
		return false
	}
	defer client.Close()
	resp, err := client.Raw().MatcherReady(ctx, &model.MatchRequest{})
	return err == nil && resp != nil && resp.Ready
}

func (m externalMatcher) Applicable(ctx context.Context, req model.MatchRequest) (bool, error) {
	ctx = launchContext(ctx, m.launchCtx)
	client, err := startPlugin(ctx, m.info.Entrypoint)
	if err != nil {
		return false, err
	}
	defer client.Close()
	resp, err := client.Raw().MatcherApplicable(ctx, &req)
	return resp != nil && resp.Applicable, err
}

func (m externalMatcher) Match(ctx context.Context, req model.MatchRequest) (model.MatchResult, error) {
	ctx = launchContext(ctx, m.launchCtx)
	client, err := startPlugin(ctx, m.info.Entrypoint)
	if err != nil {
		return model.MatchResult{}, err
	}
	defer client.Close()
	resp, err := client.Raw().Match(ctx, &req)
	if err != nil {
		return model.MatchResult{}, fmt.Errorf("run external matcher %s: %w", m.info.ID, err)
	}
	if resp == nil {
		return model.MatchResult{}, nil
	}
	return *resp, nil
}

func newExternalMatcher(info PluginInfo, ctx context.Context) model.Matcher {
	return externalMatcher{info: info, launchCtx: launchContext(ctx, nil)}
}

type externalAuditor struct {
	info      PluginInfo
	launchCtx context.Context
}

func (a externalAuditor) Metadata(context.Context) (*plugschema.PluginMetadata, error) {
	return metadataFromPluginInfo(a.info), nil
}

func (a externalAuditor) Descriptor() model.AuditorDescriptor {
	if a.info.AuditorDescriptor == nil {
		return model.AuditorDescriptor{}
	}
	return *cloneAuditorDescriptor(a.info.AuditorDescriptor)
}

func (a externalAuditor) Ready() bool {
	ctx := launchContext(context.Background(), a.launchCtx)
	client, err := startPlugin(ctx, a.info.Entrypoint)
	if err != nil {
		return false
	}
	defer client.Close()
	resp, err := client.Raw().AuditorReady(ctx, &model.AuditRequest{})
	return err == nil && resp != nil && resp.Ready
}

func (a externalAuditor) Applicable(ctx context.Context, req model.AuditRequest) (bool, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, err := startPlugin(ctx, a.info.Entrypoint)
	if err != nil {
		return false, err
	}
	defer client.Close()
	resp, err := client.Raw().AuditorApplicable(ctx, &req)
	return resp != nil && resp.Applicable, err
}

func (a externalAuditor) Audit(ctx context.Context, req model.AuditRequest) (model.AuditResult, error) {
	ctx = launchContext(ctx, a.launchCtx)
	client, err := startPlugin(ctx, a.info.Entrypoint)
	if err != nil {
		return model.AuditResult{}, err
	}
	defer client.Close()
	resp, err := client.Raw().Audit(ctx, &req)
	if err != nil {
		return model.AuditResult{}, fmt.Errorf("run external auditor %s: %w", a.info.ID, err)
	}
	if resp == nil {
		return model.AuditResult{}, nil
	}
	return *resp, nil
}

func newExternalAuditor(info PluginInfo, ctx context.Context) model.Auditor {
	return externalAuditor{info: info, launchCtx: launchContext(ctx, nil)}
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

func metadataFromPluginInfo(info PluginInfo) *plugschema.PluginMetadata {
	return &plugschema.PluginMetadata{
		ID:                     info.ID,
		Name:                   info.Name,
		Version:                info.Version,
		Kind:                   info.Kind,
		PluginAPIVersion:       info.PluginAPIVersion,
		BomlyVersionConstraint: info.BomlyVersion,
		Description:            info.Description,
		Homepage:               info.Homepage,
		License:                info.License,
	}
}
