package main

// Behavioral coverage for the install scripts: builds a fake release archive
// and installs it through the scripts' BOMLY_INSTALL_ARCHIVE seam (which
// bypasses download and checksum verification only when that variable is
// explicitly set), then asserts the binary and the full license set land
// where each script promises. No network and no sudo: install directories
// are pre-created writable temp dirs, so the scripts' privilege-escalation
// paths are never taken.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// installDocFixtures is the license set every install must deliver, mapped to
// distinctive contents so the assertions catch truncated or swapped files.
var installDocFixtures = map[string]string{
	"LICENSE":              "fixture source license\n",
	"NOTICE":               "fixture notice\n",
	"licenses/example.txt": "fixture third-party license\n",
}

func installScriptPath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	if err != nil {
		t.Fatalf("resolving scripts/%s: %v", name, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat scripts/%s: %v", name, err)
	}
	return path
}

// buildInstallTarball writes a minimal release-shaped tar.gz: an executable
// fake bomly binary plus the license set, mirroring the archive layout
// GoReleaser produces for Unix targets.
func buildInstallTarball(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "bomly_0.0.0-test_local.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating fixture archive: %v", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	writeEntry := func(name, contents string, mode int64) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(contents))}); err != nil {
			t.Fatalf("writing tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(contents)); err != nil {
			t.Fatalf("writing tar entry %s: %v", name, err)
		}
	}

	writeEntry("bomly", "#!/bin/sh\necho fake bomly\n", 0o755)
	for name, contents := range installDocFixtures {
		writeEntry(name, contents, 0o644)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}
	return path
}

// buildInstallZip writes the Windows-shaped counterpart: bomly.exe plus the
// license set at the archive root.
func buildInstallZip(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "bomly_0.0.0-test_local.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating fixture archive: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	writeEntry := func(name, contents string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(contents)); err != nil {
			t.Fatalf("writing zip entry %s: %v", name, err)
		}
	}

	writeEntry("bomly.exe", "fake bomly binary\n")
	for name, contents := range installDocFixtures {
		writeEntry(name, contents)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip writer: %v", err)
	}
	return path
}

func assertInstalledDocs(t *testing.T, docDir string) {
	t.Helper()

	for rel, want := range installDocFixtures {
		got, err := os.ReadFile(filepath.Join(docDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("doc file %s was not installed into %s: %v", rel, docDir, err)
			continue
		}
		if string(got) != want {
			t.Errorf("doc file %s content = %q, want %q", rel, got, want)
		}
	}
}

func TestInstallScriptSyntax(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is not exercised on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}

	out, err := exec.Command(bash, "-n", installScriptPath(t, "install.sh")).CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n scripts/install.sh failed: %v\n%s", err, out)
	}
}

func TestInstallScriptInstallsBinaryAndDocs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is not exercised on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}

	script := installScriptPath(t, "install.sh")
	archive := buildInstallTarball(t, t.TempDir())

	cases := []struct {
		name string
		// installDir and docDir are relative to the per-case temp root;
		// docDir encodes the script's contract: a */bin install dir gets
		// <prefix>/share/doc/bomly, anything else gets <dir>/bomly-docs.
		installDir string
		docDir     string
	}{
		{
			name:       "plain install dir gets bomly-docs",
			installDir: "tools",
			docDir:     filepath.Join("tools", "bomly-docs"),
		},
		{
			name:       "bin install dir gets share/doc/bomly",
			installDir: filepath.Join("prefix", "bin"),
			docDir:     filepath.Join("prefix", "share", "doc", "bomly"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			installDir := filepath.Join(root, tc.installDir)
			// Pre-create the install dir so it is writable and the script
			// never reaches for sudo.
			if err := os.MkdirAll(installDir, 0o755); err != nil {
				t.Fatalf("creating install dir: %v", err)
			}

			cmd := exec.Command(bash, script)
			cmd.Env = append(os.Environ(),
				"BOMLY_INSTALL_ARCHIVE="+archive,
				"BOMLY_INSTALL_DIR="+installDir,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("install.sh failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "notice: BOMLY_INSTALL_ARCHIVE is set") {
				t.Errorf("install.sh did not announce the local-archive bypass; output:\n%s", out)
			}

			binary := filepath.Join(installDir, "bomly")
			info, err := os.Stat(binary)
			if err != nil {
				t.Fatalf("installed binary missing: %v", err)
			}
			if info.Mode()&0o111 == 0 {
				t.Errorf("installed binary %s is not executable (mode %v)", binary, info.Mode())
			}

			assertInstalledDocs(t, filepath.Join(root, tc.docDir))
		})
	}
}

// TestInstallPowerShellScriptInstallsBinaryAndDocs mirrors the Unix coverage
// for scripts/install.ps1. It requires PowerShell (pwsh), which is absent on
// many dev machines but preinstalled on the ubuntu CI runners, so locally it
// usually skips while CI exercises it.
func TestInstallPowerShellScriptInstallsBinaryAndDocs(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not available")
	}

	script := installScriptPath(t, "install.ps1")
	archive := buildInstallZip(t, t.TempDir())
	installDir := filepath.Join(t.TempDir(), "Bomly", "bin")

	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", script)
	cmd.Env = append(os.Environ(),
		"BOMLY_INSTALL_ARCHIVE="+archive,
		"BOMLY_INSTALL_DIR="+installDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.ps1 failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "notice: BOMLY_INSTALL_ARCHIVE is set") {
		t.Errorf("install.ps1 did not announce the local-archive bypass; output:\n%s", out)
	}

	if _, err := os.Stat(filepath.Join(installDir, "bomly.exe")); err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}

	// install.ps1 keeps the docs in a doc subfolder of the install dir.
	assertInstalledDocs(t, filepath.Join(installDir, "doc"))
}
