package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-sdk"
)

func TestDetectPackageManagersDoesNotGuessPDMFromUnreadablePyproject(t *testing.T) {
	projectDir := t.TempDir()
	pyprojectPath := filepath.Join(projectDir, "pyproject.toml")
	file, err := os.Create(pyprojectPath) // #nosec G304 -- test path is created under t.TempDir
	if err != nil {
		t.Fatalf("create oversized pyproject.toml: %v", err)
	}
	if err := file.Truncate(system.MaxRepositoryFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized pyproject.toml: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized pyproject.toml: %v", err)
	}

	managers, err := DetectPackageManagers(projectDir)
	if err != nil {
		t.Fatalf("DetectPackageManagers() error = %v", err)
	}
	if containsPackageManager(managers, sdk.PackageManagerPDM) {
		t.Fatalf("DetectPackageManagers() = %#v, must not infer PDM from unreadable pyproject.toml", managers)
	}
}

func containsPackageManager(managers []sdk.PackageManager, target sdk.PackageManager) bool {
	for _, manager := range managers {
		if manager == target {
			return true
		}
	}
	return false
}
