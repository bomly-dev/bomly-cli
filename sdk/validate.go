package sdk

import (
	"fmt"
	"strings"
)

// ValidateMetadata validates plugin runtime metadata exposed through the SDK.
func ValidateMetadata(metadata *PluginMetadata) error {
	if metadata == nil {
		return fmt.Errorf("plugin metadata is nil")
	}
	if strings.TrimSpace(metadata.ID) == "" {
		return fmt.Errorf("plugin metadata id is required")
	}
	switch metadata.Kind {
	case PluginKindDetector, PluginKindMatcher, PluginKindAuditor, PluginKindAnalyzer:
	default:
		return fmt.Errorf("plugin metadata kind %q is invalid", metadata.Kind)
	}
	if apiVersion := strings.TrimSpace(metadata.PluginAPIVersion); apiVersion != PluginAPIVersion {
		return fmt.Errorf("plugin metadata API version %q is unsupported", apiVersion)
	}
	return nil
}

// ValidateDetectorDescriptor validates typed detector registration data.
func ValidateDetectorDescriptor(descriptor *DetectorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("detector descriptor is nil")
	}
	if strings.TrimSpace(descriptor.Name) == "" {
		return fmt.Errorf("detector descriptor name is required")
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("detector descriptor supported managers must not contain empty values")
		}
	}
	for _, support := range descriptor.PackageManagerSupport {
		if strings.TrimSpace(support.PackageManager.Name()) == "" {
			return fmt.Errorf("detector descriptor package manager support must not contain empty package manager values")
		}
	}
	for _, fallback := range descriptor.FallbackDetectors {
		if strings.TrimSpace(fallback) == "" {
			return fmt.Errorf("detector descriptor fallback detectors must not contain empty values")
		}
	}
	return nil
}

// ValidateMatcherDescriptor validates typed matcher registration data.
func ValidateMatcherDescriptor(descriptor *MatcherDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("matcher descriptor is nil")
	}
	if strings.TrimSpace(descriptor.Name) == "" {
		return fmt.Errorf("matcher descriptor name is required")
	}
	for _, alias := range descriptor.Aliases {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("matcher descriptor aliases must not contain empty values")
		}
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("matcher descriptor supported managers must not contain empty values")
		}
	}
	return nil
}

// ValidateAuditorDescriptor validates typed auditor registration data.
func ValidateAuditorDescriptor(descriptor *AuditorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("auditor descriptor is nil")
	}
	if strings.TrimSpace(descriptor.Name) == "" {
		return fmt.Errorf("auditor descriptor name is required")
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("auditor descriptor supported managers must not contain empty values")
		}
	}
	return nil
}
