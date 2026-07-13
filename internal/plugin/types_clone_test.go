package plugin

import (
	"testing"

	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

func TestCloneDetectorDescriptorDeepCopiesDiscoveryFields(t *testing.T) {
	original := &plugschema.DetectorDescriptor{
		Name:                    "example",
		IgnoredDirectories:      []string{"node_modules"},
		IgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		PackageManagerSupport: []plugschema.PackageManagerSupport{
			plugschema.Support(plugschema.PackageManagerNPM, "package.json").WithMultiModule(),
		},
	}
	clone := cloneDetectorDescriptor(original)

	if got := clone.IgnoredDirectories; len(got) != 1 || got[0] != "node_modules" {
		t.Fatalf("expected cloned ignored directories, got %#v", got)
	}
	if got := clone.IgnoredDirectoryMarkers; len(got) != 1 || got[0] != "pyvenv.cfg" {
		t.Fatalf("expected cloned ignored directory markers, got %#v", got)
	}
	if len(clone.PackageManagerSupport) != 1 || !clone.PackageManagerSupport[0].MultiModule {
		t.Fatalf("expected MultiModule to survive cloning, got %#v", clone.PackageManagerSupport)
	}

	// Mutating the clone's slices must not touch the original.
	clone.IgnoredDirectories[0] = "mutated"
	clone.IgnoredDirectoryMarkers[0] = "mutated"
	if original.IgnoredDirectories[0] != "node_modules" || original.IgnoredDirectoryMarkers[0] != "pyvenv.cfg" {
		t.Fatal("clone shares backing arrays with the original descriptor")
	}
}
