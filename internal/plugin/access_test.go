package plugin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"

	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

func accessTestManifest(access *sdkplugin.Access) Manifest {
	return withCanonicalManifestDefaults(Manifest{
		ID:         "acme.matcher.access",
		Name:       "acme access matcher",
		Version:    "1.0.0",
		Kind:       sdkplugin.PluginKindMatcher,
		Entrypoint: map[string]string{platformKey(): "bin/matcher"},
		Access:     access,
	}, "test")
}

func TestValidateManifestDelegatesAccessToTheSDKGate(t *testing.T) {
	if err := validateManifest(accessTestManifest(nil)); err != nil {
		t.Fatalf("a legacy manifest without an access block must stay valid: %v", err)
	}
	if err := validateManifest(accessTestManifest(&sdkplugin.Access{})); err != nil {
		t.Fatalf("an empty block, a claim of no access, must be valid: %v", err)
	}
	valid := &sdkplugin.Access{Network: []string{"*.github.com", "api.osv.dev"}, Environment: []string{"BOMLY_HTTP_*"}, Subprocesses: []string{"go"}}
	if err := validateManifest(accessTestManifest(valid)); err != nil {
		t.Fatalf("validateManifest() rejected a well-formed disclosure: %v", err)
	}
	for name, access := range map[string]*sdkplugin.Access{
		"host with a path":     {Network: []string{"example.com/path"}},
		"environment value":    {Environment: []string{"TOKEN=secret"}},
		"command with a path":  {Subprocesses: []string{"/usr/bin/go"}},
		"too many entries":     {Subprocesses: slices.Repeat([]string{"go"}, sdkplugin.MaxAccessEntries+1)},
		"malformed scope name": {FilesystemRead: []sdkplugin.FilesystemScope{"Project Dir"}},
	} {
		err := validateManifest(accessTestManifest(access))
		if err == nil || !strings.Contains(err.Error(), "plugin manifest access") {
			t.Errorf("%s: validateManifest() = %v, want the SDK's access error", name, err)
		}
	}
}

func TestManifestAccessDisclosureNeverReadsAbsenceAsNoAccess(t *testing.T) {
	if got := accessTestManifest(nil).AccessDisclosure(); got != AccessUnknown {
		t.Fatalf("absent access block = %q, want %q", got, AccessUnknown)
	}
	if got := accessTestManifest(&sdkplugin.Access{}).AccessDisclosure(); got != AccessDeclared {
		t.Fatalf("empty access block = %q, want %q", got, AccessDeclared)
	}
}

func TestInstallKeepsTheDeclaredAccessAndRefusesAMalformedOne(t *testing.T) {
	binaryName := "bomly-plugin-access"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	if err := testutil.BuildGoBinary(t, binaryPath, fakeDetectorPluginSource("acme.detector.access")); err != nil {
		t.Fatalf("build fake plugin: %v", err)
	}
	install := func(t *testing.T, root string, access *sdkplugin.Access) (*InstallResult, error) {
		t.Helper()
		manifest := withCanonicalManifestDefaults(Manifest{
			ID:         "acme.detector.access",
			Name:       "Acme Access Detector",
			Version:    "1.0.0",
			Kind:       sdkplugin.PluginKindDetector,
			Entrypoint: map[string]string{platformKey(): filepath.ToSlash(filepath.Join("bin", binaryName))},
			Access:     access,
		}, "local")
		archive := filepath.Join(t.TempDir(), "plugin"+archiveSuffix())
		if err := os.WriteFile(archive, buildPluginArchive(t, manifest, binaryPath), 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		return Install(context.Background(), root, archive, InstallOptions{})
	}

	t.Run("declared", func(t *testing.T) {
		root := t.TempDir()
		if _, err := install(t, root, &sdkplugin.Access{Network: []string{"API.Example.COM", "api.example.com"}, Subprocesses: []string{"go"}}); err != nil {
			t.Fatalf("Install() error = %v", err)
		}
		installed, err := LoadInstalledPlugins(root)
		if err != nil || len(installed) != 1 {
			t.Fatalf("LoadInstalledPlugins() = %v, %v", installed, err)
		}
		info := installed[0]
		if info.AccessDisclosure != AccessDeclared || info.Access == nil || !slices.Equal(info.Access.Network, []string{"api.example.com"}) {
			t.Fatalf("the installed disclosure must be the SDK-normalized declaration, got %q %+v", info.AccessDisclosure, info.Access)
		}
	})
	t.Run("legacy", func(t *testing.T) {
		root := t.TempDir()
		if _, err := install(t, root, nil); err != nil {
			t.Fatalf("a manifest without an access block must keep installing: %v", err)
		}
		installed, err := LoadInstalledPlugins(root)
		if err != nil || len(installed) != 1 || installed[0].AccessDisclosure != AccessUnknown || installed[0].Access != nil {
			t.Fatalf("legacy install must read as unknown, got %+v, %v", installed, err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		root := t.TempDir()
		_, err := install(t, root, &sdkplugin.Access{Network: []string{"not a host"}})
		if err == nil || !strings.Contains(err.Error(), "access network entry") {
			t.Fatalf("a malformed declaration must fail the install, not be dropped: %v", err)
		}
		if installed, _ := LoadInstalledPlugins(root); len(installed) != 0 {
			t.Fatalf("a refused install must leave nothing installed, got %+v", installed)
		}
	})
}

func TestRuntimeSnapshotComparisonIncludesRequirements(t *testing.T) {
	left := &sdkplugin.MatcherDescriptor{Name: "m", Requires: sdkplugin.Requirements{sdkplugin.RequirementDependencyGraph}}
	same := &sdkplugin.MatcherDescriptor{Name: "m", Requires: sdkplugin.Requirements{sdkplugin.RequirementDependencyGraph, sdkplugin.RequirementDependencyGraph}}
	changed := &sdkplugin.MatcherDescriptor{Name: "m", Requires: sdkplugin.Requirements{sdkplugin.RequirementSourceTree}}
	if !matcherDescriptorEqual(left, same) {
		t.Fatal("requirements equal after normalization must compare equal")
	}
	if matcherDescriptorEqual(left, changed) {
		t.Fatal("a binary whose declared requirements changed since install must not match its snapshot")
	}
	clone := cloneMatcherDescriptor(left)
	clone.Requires[0] = sdkplugin.RequirementSourceTree
	if left.Requires[0] != sdkplugin.RequirementDependencyGraph {
		t.Fatal("a cloned descriptor must not share its requirements with the original")
	}
}
