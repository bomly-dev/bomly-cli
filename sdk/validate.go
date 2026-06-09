package sdk

import (
	"fmt"
	"strings"
)

// ValidateDetectorDescriptor validates typed detector registration data.
func ValidateDetectorDescriptor(descriptor *DetectorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("detector descriptor is nil")
	}
	if err := validateComponentDescriptor("detector", componentFromDetectorDescriptor(*descriptor)); err != nil {
		return err
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
	return validateComponentDescriptor("matcher", componentFromMatcherDescriptor(*descriptor))
}

// ValidateAuditorDescriptor validates typed auditor registration data.
func ValidateAuditorDescriptor(descriptor *AuditorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("auditor descriptor is nil")
	}
	return validateComponentDescriptor("auditor", componentFromAuditorDescriptor(*descriptor))
}

func validateComponentDescriptor(kind string, descriptor ComponentDescriptor) error {
	if strings.TrimSpace(descriptor.Name) == "" {
		return fmt.Errorf("%s descriptor name is required", kind)
	}
	for _, alias := range descriptor.Aliases {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("%s descriptor aliases must not contain empty values", kind)
		}
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("%s descriptor supported managers must not contain empty values", kind)
		}
	}
	return nil
}

func componentFromDetectorDescriptor(descriptor DetectorDescriptor) ComponentDescriptor {
	return ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func componentFromMatcherDescriptor(descriptor MatcherDescriptor) ComponentDescriptor {
	return ComponentDescriptor(descriptor)
}

func componentFromAuditorDescriptor(descriptor AuditorDescriptor) ComponentDescriptor {
	return ComponentDescriptor(descriptor)
}
