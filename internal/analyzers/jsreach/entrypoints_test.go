package jsreach

import (
	"os"
	"path/filepath"
	"testing"
)

func writePackage(t *testing.T, dir, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, dir, name, contents string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverEntryPointsExplicitMain(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"main":"src/server.js"}`)
	writeFile(t, dir, "src/server.js", "module.exports = {};")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || filepath.Base(entries[0]) != "server.js" {
		t.Errorf("entries = %v, want one server.js", entries)
	}
}

func TestDiscoverEntryPointsBinAsString(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"bin":"./cli.js"}`)
	writeFile(t, dir, "cli.js", "#!/usr/bin/env node")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || filepath.Base(entries[0]) != "cli.js" {
		t.Errorf("entries = %v, want one cli.js", entries)
	}
}

func TestDiscoverEntryPointsBinAsObject(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"bin":{"foo":"./bin/foo.js","bar":"./bin/bar.js"}}`)
	writeFile(t, dir, "bin/foo.js", "")
	writeFile(t, dir, "bin/bar.js", "")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("entries count = %d, want 2 (got %v)", len(entries), entries)
	}
}

func TestDiscoverEntryPointsExportsConditional(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"exports":{".":{"import":"./esm.js","require":"./cjs.js"},"./util":"./util.js"}}`)
	writeFile(t, dir, "esm.js", "")
	writeFile(t, dir, "cjs.js", "")
	writeFile(t, dir, "util.js", "")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("entries = %v, want 3", entries)
	}
}

func TestDiscoverEntryPointsImplicitIndexFallback(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"name":"fixture","version":"1.0.0"}`)
	writeFile(t, dir, "index.js", "module.exports = {};")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || filepath.Base(entries[0]) != "index.js" {
		t.Errorf("entries = %v, want one index.js", entries)
	}
}

func TestDiscoverEntryPointsErrorsWhenNoneResolve(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"main":"missing.js"}`)
	if _, err := discoverEntryPoints(dir); err == nil {
		t.Error("expected error when no entry resolves on disk")
	}
}

func TestDiscoverEntryPointsErrorsWhenPackageJSONMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := discoverEntryPoints(dir); err == nil {
		t.Error("expected error when package.json missing")
	}
}

func TestDiscoverEntryPointsDeduplicates(t *testing.T) {
	dir := t.TempDir()
	writePackage(t, dir, `{"main":"index.js","module":"index.js","exports":"./index.js"}`)
	writeFile(t, dir, "index.js", "")

	entries, err := discoverEntryPoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("entries should be deduplicated; got %v", entries)
	}
}
