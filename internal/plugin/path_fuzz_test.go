package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzPluginPathSanitizers(f *testing.F) {
	for _, seed := range []string{
		"bin/bomly-plugin",
		"../escape",
		"/absolute/path",
		`.\\`,
		`windows\path\plugin.exe`,
		"plugin.tar.gz",
		"plugin.zip",
		"C:/escape/plugin.exe",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}

		if name := safeDownloadArchiveName(raw); name != "" {
			if strings.ContainsAny(name, `/\`) {
				t.Fatalf("safe archive name contains path separator: %q from %q", name, raw)
			}
			if name == "." || name == ".." || strings.Contains(name, ":") {
				t.Fatalf("safe archive name is unsafe: %q from %q", name, raw)
			}
			switch ext := archiveExtension(name); ext {
			case "", ".zip", ".tar.gz", ".tgz":
			default:
				t.Fatalf("unexpected archive extension %q for %q", ext, name)
			}
		}

		cleanPath, err := cleanRelativePluginPath(raw)
		if err != nil {
			return
		}
		if cleanPath == "" || cleanPath == "." || filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, ":") {
			t.Fatalf("clean relative path is unsafe: %q from %q", cleanPath, raw)
		}
		if cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(os.PathSeparator)) {
			t.Fatalf("clean relative path escapes base: %q from %q", cleanPath, raw)
		}

		root := t.TempDir()
		fullPath, err := pathInPluginDir(root, raw)
		if err != nil {
			t.Fatalf("pathInPluginDir rejected path accepted by cleanRelativePluginPath: %q: %v", raw, err)
		}
		rel, err := filepath.Rel(root, fullPath)
		if err != nil {
			t.Fatalf("rel path for %q: %v", fullPath, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Fatalf("pathInPluginDir returned escaping path: root=%q full=%q rel=%q", root, fullPath, rel)
		}
	})
}
