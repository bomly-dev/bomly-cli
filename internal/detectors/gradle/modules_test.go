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

// TestWalkGradleSettingsModulesIgnoresCommentedIncludes pins the review
// finding: a commented-out include must not register a module — a nonexistent
// `:removed:dependencies` task would fail the whole multi-project invocation
// and throw away every legitimate module through the root-only fallback.
func TestWalkGradleSettingsModulesIgnoresCommentedIncludes(t *testing.T) {
	root := t.TempDir()
	writeGradleFile(t, root, "settings.gradle", `rootProject.name = 'demo'
// include(":removed")
//include ':also-removed'
/*
include(":block-removed")
project(":block-removed").projectDir = file("elsewhere")
*/
include(":app") // trailing comments are fine
println "include(':fake')"
val banner = """
include(":ghost")
"""
include ':lib'
`)
	writeGradleFile(t, root, "app/build.gradle", "dependencies {}\n")
	writeGradleFile(t, root, "lib/build.gradle", "dependencies {}\n")

	modules, err := walkGradleSettingsModules(root)
	if err != nil {
		t.Fatalf("walkGradleSettingsModules() error = %v", err)
	}
	if got := gradleModuleDirs(modules); !reflect.DeepEqual(got, []string{"app", "lib"}) {
		t.Fatalf("module dirs = %v, want [app lib] (commented/string includes must be ignored)", got)
	}
}

func TestStripGradleComments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "line comment", in: "include(\":a\") // include(\":b\")\n", want: "include(\":a\") \n"},
		{name: "block comment keeps newlines", in: "a /* x\ny */ b", want: "a \n b"},
		{name: "comment markers inside strings survive", in: "name = 'http://example.com' // gone", want: "name = 'http://example.com' "},
		{name: "escaped quote does not end string", in: `id = "a\"//b" // gone`, want: `id = "a\"//b" `},
		{name: "unterminated string passes through", in: "x = 'abc", want: "x = 'abc"},
		{name: "kotlin raw string blanked to newlines", in: "val s = \"\"\"\ninclude(\":ghost\")\n\"\"\"\ninclude(\":real\")", want: "val s = \n\n\ninclude(\":real\")"},
		{name: "groovy triple string blanked", in: "def s = '''\ninclude ':ghost'\n'''", want: "def s = \n\n"},
		{name: "empty string pair is not a triple quote", in: `a = "" + "b"`, want: `a = "" + "b"`},
		{name: "unterminated triple string blanked to end", in: "s = \"\"\"\ninclude(\":ghost\")", want: "s = \n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripGradleComments(tc.in); got != tc.want {
				t.Fatalf("stripGradleComments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
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
