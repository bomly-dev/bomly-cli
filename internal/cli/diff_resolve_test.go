package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveContainerDiffTarget(t *testing.T) {
	dir := t.TempDir()
	localFile := filepath.Join(dir, "image.sbom.json")
	if err := os.WriteFile(localFile, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	tests := map[string]struct {
		container string
		selector  string
		want      string
	}{
		"tag":       {container: "alpine", selector: "3.20", want: "alpine:3.20"},
		"digest":    {container: "alpine", selector: "sha256:abc", want: "alpine@sha256:abc"},
		"reference": {container: "ignored", selector: "ghcr.io/acme/app:1", want: "ghcr.io/acme/app:1"},
		"local":     {container: "ignored", selector: localFile, want: localFile},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := resolveContainerDiffTarget(tt.container, tt.selector)
			if err != nil {
				t.Fatalf("resolveContainerDiffTarget() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestResolveContainerDiffTargetRejectsEmptyValues(t *testing.T) {
	if _, err := resolveContainerDiffTarget("alpine", ""); err == nil {
		t.Fatal("expected empty selector error")
	}
	if _, err := resolveContainerDiffTarget("", "3.20"); err == nil {
		t.Fatal("expected empty container error")
	}
}
