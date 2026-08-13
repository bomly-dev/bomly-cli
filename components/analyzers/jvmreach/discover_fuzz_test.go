package jvmreach

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzReadMavenProject verifies that the Maven pom.xml module reader
// never panics and produces deterministic results for arbitrary
// (valid, malformed, or truncated) XML input within the shared fuzz
// input bound. The reader is file-backed, so each iteration writes the
// input as pom.xml in a fresh temp dir and reads it back twice.
func FuzzReadMavenProject(f *testing.F) {
	for _, seed := range []string{
		"",
		`<project><groupId>com.example</groupId><artifactId>app</artifactId></project>`,
		`<project><parent><groupId>com.example</groupId></parent><artifactId>child</artifactId><modules><module>core</module><module>../escape</module></modules></project>`,
		`<project><modules><module>a</module>`,
		`not xml at all`,
		"<project>\xff\xfe</project>",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), data, 0o600); err != nil {
			t.Fatalf("write pom.xml: %v", err)
		}
		first, firstOK := readMavenProject(dir)
		second, secondOK := readMavenProject(dir)
		if firstOK != secondOK {
			t.Fatalf("read changed success state: first=%v second=%v", firstOK, secondOK)
		}
		if !firstOK {
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("read changed result for identical input")
		}
	})
}

// FuzzReadGradleModules verifies that the Gradle settings module reader
// never panics and produces deterministic results for arbitrary
// (valid, malformed, or truncated) settings-script input within the
// shared fuzz input bound. Determinism matters here because the reader
// collects modules through a map; its output order must not depend on
// Go's randomized map iteration.
func FuzzReadGradleModules(f *testing.F) {
	for _, seed := range []string{
		"",
		`include ':core', ':app'`,
		"include(\":a\")\ninclude ':b'\nproject(':a').projectDir = file('modules/a')\n",
		`include ':escape'` + "\n" + `project(':escape').projectDir = file('../outside')`,
		`include "unterminated`,
		"rootProject.name = 'demo'\n/* include ':commented' */\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "settings.gradle"), data, 0o600); err != nil {
			t.Fatalf("write settings.gradle: %v", err)
		}
		first := readGradleModules(root)
		second := readGradleModules(root)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("read changed result for identical input")
		}
		for _, module := range first {
			if !pathContainsRoot(module.Dir, root) {
				t.Fatalf("module dir %q escapes root %q", module.Dir, root)
			}
		}
	})
}
