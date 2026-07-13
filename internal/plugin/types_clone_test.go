package plugin

import (
	"testing"

	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

func TestCloneDetectorDescriptorDeepCopiesDiscoveryFields(t *testing.T) {
	original := &plugschema.DetectorDescriptor{
		Name:                             "example",
		DiscoveryIgnoredDirectories:      []string{"node_modules"},
		DiscoveryIgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		PackageManagerSupport: []plugschema.PackageManagerSupport{
			plugschema.Support(plugschema.PackageManagerNPM, "package.json").WithNativeMultiModule(),
		},
	}
	clone := cloneDetectorDescriptor(original)

	if got := clone.DiscoveryIgnoredDirectories; len(got) != 1 || got[0] != "node_modules" {
		t.Fatalf("expected cloned ignored directories, got %#v", got)
	}
	if got := clone.DiscoveryIgnoredDirectoryMarkers; len(got) != 1 || got[0] != "pyvenv.cfg" {
		t.Fatalf("expected cloned ignored directory markers, got %#v", got)
	}
	if len(clone.PackageManagerSupport) != 1 || !clone.PackageManagerSupport[0].NativeMultiModule {
		t.Fatalf("expected NativeMultiModule to survive cloning, got %#v", clone.PackageManagerSupport)
	}

	// Mutating the clone's slices must not touch the original.
	clone.DiscoveryIgnoredDirectories[0] = "mutated"
	clone.DiscoveryIgnoredDirectoryMarkers[0] = "mutated"
	if original.DiscoveryIgnoredDirectories[0] != "node_modules" || original.DiscoveryIgnoredDirectoryMarkers[0] != "pyvenv.cfg" {
		t.Fatal("clone shares backing arrays with the original descriptor")
	}
}
