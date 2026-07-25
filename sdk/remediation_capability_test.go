package sdk

import (
	"strings"
	"testing"
)

func TestValidateDetectorDescriptorRemediationCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		capability RemediationCapability
		wantError  string
	}{
		{
			name: "valid",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
				Actions:           []RemediationAction{RemediationActionDirectBump},
			},
		},
		{
			name:       "missing manager",
			capability: RemediationCapability{Actions: []RemediationAction{RemediationActionDirectBump}},
			wantError:  "package manager",
		},
		{
			name: "empty manager",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerUnknown},
				Actions:           []RemediationAction{RemediationActionDirectBump},
			},
			wantError: "empty",
		},
		{
			name: "missing action",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
			},
			wantError: "action",
		},
		{
			name: "central-only action",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
				Actions:           []RemediationAction{RemediationActionManualReview},
			},
			wantError: "invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDetectorDescriptor(&DetectorDescriptor{
				Name:                    "test-detector",
				RemediationCapabilities: []RemediationCapability{test.capability},
			})
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ValidateDetectorDescriptor() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateDetectorDescriptor() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestProtocolV1DetectorDescriptorLeavesRemediationOptional(t *testing.T) {
	descriptor := DetectorDescriptor{
		Name:              "legacy-detector",
		SupportedManagers: []PackageManager{PackageManagerNPM},
	}
	if err := ValidateDetectorDescriptor(&descriptor); err != nil {
		t.Fatalf("ValidateDetectorDescriptor() rejected legacy descriptor: %v", err)
	}
	if descriptor.RemediationCapabilities != nil {
		t.Fatalf("legacy descriptor gained remediation capabilities: %#v", descriptor)
	}
}

func TestDetectorDescriptorCloneDeepCopiesRemediationCapabilities(t *testing.T) {
	descriptor := DetectorDescriptor{
		Name: "test-detector",
		RemediationCapabilities: []RemediationCapability{{
			SupportedManagers: []PackageManager{PackageManagerNPM},
			Actions:           []RemediationAction{RemediationActionDirectBump},
		}},
	}
	clone := descriptor.Clone()
	clone.RemediationCapabilities[0].SupportedManagers[0] = PackageManagerGoMod
	clone.RemediationCapabilities[0].Actions[0] = RemediationActionLockfileRefresh
	if descriptor.RemediationCapabilities[0].SupportedManagers[0] != PackageManagerNPM ||
		descriptor.RemediationCapabilities[0].Actions[0] != RemediationActionDirectBump {
		t.Fatalf("Clone() shared remediation capability slices: %#v", descriptor)
	}
}
