package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMetadata_Valid(t *testing.T) {
	data := []byte(`{"name":"npm","version":"0.1.0","protocol":"v1","commands":[{"name":"deps","summary":"Print dependency graph"}]}`)

	md, err := ParseMetadata(data)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if md.Name != "npm" {
		t.Fatalf("expected name npm, got %q", md.Name)
	}
	if len(md.Commands) != 1 || md.Commands[0].Name != "deps" {
		t.Fatalf("unexpected commands: %#v", md.Commands)
	}
}

func TestParseMetadata_ValidWithDiscoveryMetadata(t *testing.T) {
	data := []byte(`{"name":"custom","version":"0.1.0","protocol":"v1","commands":[{"name":"deps","stage":"detect","ecosystems":["npm"],"package_managers":["npm"],"evidence_patterns":["package.json"],"target_kinds":["filesystem"]}]}`)

	md, err := ParseMetadata(data)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if len(md.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(md.Commands))
	}
	if got := md.Commands[0].Ecosystems; len(got) != 1 || got[0] != "npm" {
		t.Fatalf("unexpected ecosystems metadata: %#v", got)
	}
	if got := md.Commands[0].TargetKinds; len(got) != 1 || got[0] != "filesystem" {
		t.Fatalf("unexpected target kinds metadata: %#v", got)
	}
}

func TestParseMetadata_InvalidProtocol(t *testing.T) {
	data := []byte(`{"name":"npm","version":"0.1.0","protocol":"v2","commands":[{"name":"deps"}]}`)

	if _, err := ParseMetadata(data); err == nil {
		t.Fatal("expected protocol validation error")
	}
}

func TestDiscover_UserDirOverridesPath(t *testing.T) {
	tempHome := t.TempDir()
	userPluginDir := filepath.Join(tempHome, ".bomly", "plugins")
	if err := os.MkdirAll(userPluginDir, 0o755); err != nil {
		t.Fatalf("mkdir user plugin dir: %v", err)
	}
	userPluginPath := filepath.Join(userPluginDir, "bomly-npm")
	if err := os.WriteFile(userPluginPath, []byte("x"), 0o755); err != nil {
		t.Fatalf("write user plugin stub: %v", err)
	}

	tempPathDir := t.TempDir()
	pathPluginPath := filepath.Join(tempPathDir, "bomly-npm")
	if err := os.WriteFile(pathPluginPath, []byte("x"), 0o755); err != nil {
		t.Fatalf("write path plugin stub: %v", err)
	}

	plugins, err := Discover(DiscoverOptions{
		HomeDir: tempHome,
		PathEnv: tempPathDir,
		MetadataLoader: func(path string) (Metadata, error) {
			if path == userPluginPath {
				return Metadata{Name: "npm", Version: "user", Protocol: "v1", Commands: []Command{{Name: "deps"}}}, nil
			}
			return Metadata{Name: "npm", Version: "path", Protocol: "v1", Commands: []Command{{Name: "deps"}}}, nil
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Path != userPluginPath {
		t.Fatalf("expected user plugin to win, got %q", plugins[0].Path)
	}
}
