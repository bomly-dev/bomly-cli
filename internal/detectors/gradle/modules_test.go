package gradle

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeGradleFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func gradleModuleDirs(modules []gradleModule) []string {
	dirs := make([]string, 0, len(modules))
	for _, module := range modules {
		dirs = append(dirs, module.Dir)
	}
	return dirs
}

func TestWalkGradleSettingsModulesParenthesizedInclude(t *testing.T) {
	root := t.TempDir()
	writeGradleFile(t, root, "settings.gradle", "rootProject.name = 'demo'\ninclude(\":app\", \":lib\")\n")
	writeGradleFile(t, root, "build.gradle", "group = \"com.acme\"\n")
	writeGradleFile(t, root, "app/build.gradle", "dependencies {}\n")
	writeGradleFile(t, root, "lib/build.gradle.kts", "group = \"com.acme.libs\"\n")

	modules, err := walkGradleSettingsModules(root)
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if got := gradleModuleDirs(modules); !reflect.DeepEqual(got, []string{"app", "lib"}) {
		t.Fatalf("module dirs = %v, want [app lib]", got)
	}
	app, lib := modules[0], modules[1]
	if app.ProjectPath != ":app" || app.Name != "app" || app.Group != "com.acme" || app.ManifestFile != "build.gradle" {
		t.Fatalf("unexpected app module: %#v", app)
	}
	if lib.ProjectPath != ":lib" || lib.Group != "com.acme.libs" || lib.ManifestFile != "build.gradle.kts" {
		t.Fatalf("unexpected lib module: %#v", lib)
	}
}

func TestWalkGradleSettingsModulesLineIncludeAndNesting(t *testing.T) {
	root := t.TempDir()
	writeGradleFile(t, root, "settings.gradle", "include ':services:api', ':services:worker'\ninclude ':tools'\n")
	writeGradleFile(t, root, "services/api/build.gradle", "")
	writeGradleFile(t, root, "services/worker/build.gradle", "")
	writeGradleFile(t, root, "tools/build.gradle", "")

	modules, err := walkGradleSettingsModules(root)
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if got := gradleModuleDirs(modules); !reflect.DeepEqual(got, []string{"services/api", "services/worker", "tools"}) {
		t.Fatalf("module dirs = %v", got)
	}
	if modules[0].ProjectPath != ":services:api" || modules[0].Name != "api" {
		t.Fatalf("unexpected nested module: %#v", modules[0])
	}
}

func TestWalkGradleSettingsModulesProjectDirOverride(t *testing.T) {
	root := t.TempDir()
	writeGradleFile(t, root, "settings.gradle.kts", "include(\":legacy\")\nproject(\":legacy\").projectDir = file(\"modules/legacy-code\")\n")
	writeGradleFile(t, root, "modules/legacy-code/build.gradle", "")

	modules, err := walkGradleSettingsModules(root)
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if len(modules) != 1 || modules[0].Dir != "modules/legacy-code" || modules[0].Name != "legacy" {
		t.Fatalf("unexpected override module: %#v", modules)
	}
}

func TestWalkGradleSettingsModulesSkipsEscapingPaths(t *testing.T) {
	root := t.TempDir()
	writeGradleFile(t, root, "settings.gradle", "include(\":outside\")\nproject(\":outside\").projectDir = file(\"../elsewhere\")\n")

	modules, err := walkGradleSettingsModules(root)
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if len(modules) != 0 {
		t.Fatalf("expected escaping projectDir to be skipped, got %#v", modules)
	}
}

func TestWalkGradleSettingsModulesNoSettings(t *testing.T) {
	modules, err := walkGradleSettingsModules(t.TempDir())
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if len(modules) != 0 {
		t.Fatalf("expected no modules without a settings script, got %#v", modules)
	}
}

func TestDisambiguateGradleModuleNames(t *testing.T) {
	modules := []gradleModule{
		{ProjectPath: ":a:lib", Name: "lib"},
		{ProjectPath: ":b:lib", Name: "lib"},
		{ProjectPath: ":app", Name: "app"},
	}
	disambiguateGradleModuleNames(modules)
	if modules[0].Name != "a/lib" || modules[1].Name != "b/lib" {
		t.Fatalf("expected duplicate names to use path form, got %#v", modules)
	}
	if modules[2].Name != "app" {
		t.Fatalf("unique name must keep the short form, got %q", modules[2].Name)
	}
}
