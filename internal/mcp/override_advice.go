package mcp

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// overrideAdvice returns package-manager-specific guidance for forcing a
// transitive dependency to a safe version, and whether the manager supports
// declarative overrides at all. Managers without an override mechanism get
// a refresh-style command instead (supported=false → lockfile-refresh).
// This is a pure text table — Bomly never edits manifests.
func overrideAdvice(pm string, pkg PackageIdentity, version, manifestPath string) (advice string, supported bool) {
	name := pkg.Name
	manifest := valueOr(manifestPath, "the project manifest")
	switch sdk.PackageManager(pm) {
	case sdk.PackageManagerNPM:
		// Overrides live in package.json regardless of which manifest
		// (often the lockfile) the detector reported.
		return fmt.Sprintf(`add "overrides": {%q: %q} to package.json and run npm install`, name, version), true
	case sdk.PackageManagerPNPM:
		return fmt.Sprintf(`add %q: %q under "pnpm"."overrides" in package.json (or under "overrides:" in pnpm-workspace.yaml for workspaces) and run pnpm install`, name, version), true
	case sdk.PackageManagerYarn:
		return fmt.Sprintf(`add "resolutions": {%q: %q} to package.json and run yarn install`, name, version), true
	case sdk.PackageManagerMaven:
		return fmt.Sprintf("pin %s to %s in <dependencyManagement> of %s", name, version, manifest), true
	case sdk.PackageManagerGradle:
		return fmt.Sprintf("add dependencies { constraints { implementation(%q) } } in %s", pkg.Name+":"+version, manifest), true
	case sdk.PackageManagerGoMod:
		return fmt.Sprintf("run `go get %s@v%s && go mod tidy`", name, version), false
	case sdk.PackageManagerCargo:
		return fmt.Sprintf("run `cargo update -p %s --precise %s`, or use a [patch] section for source replacement", name, version), false
	case sdk.PackageManagerPip, sdk.PackageManagerPipenv:
		return fmt.Sprintf("add a constraint `%s>=%s` to your requirements/constraints file and reinstall", name, version), true
	case sdk.PackageManagerPoetry, sdk.PackageManagerUV:
		return fmt.Sprintf("pin `%s>=%s` in pyproject.toml and refresh the lockfile", name, version), true
	case sdk.PackageManagerBundler:
		return fmt.Sprintf(`add gem %q, ">= %s" to the Gemfile and run bundle update %s`, name, version, name), true
	case sdk.PackageManagerComposer:
		return fmt.Sprintf(`require %q: %q in %s and run composer update %s`, name, "^"+version, manifest, name), true
	default:
		return fmt.Sprintf("pin transitive dependency %s to %s or newer using your package manager's override mechanism", name, version), false
	}
}
