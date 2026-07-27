package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/nodetest"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// FuzzPackageManagerWarnings exercises the project-configuration parsers behind
// PackageManagerWarnings: package.json (JSON), pnpm-workspace.yaml (YAML), and
// .npmrc (key/value). The same fuzz input is written to all three files so one
// target covers every conversion, and the call must neither panic nor produce
// multi-line messages regardless of what the repository contains.
func FuzzPackageManagerWarnings(f *testing.F) {
	f.Add(`{"name":"app","packageManager":"pnpm@10.4.1","engines":{"pnpm":">=10"}}`)
	f.Add(`{"packageManager":"yarn@4.1.0+sha512.` + "\x1b[2J" + `"}`)
	f.Add("minimumReleaseAge: 1440\npackages:\n  - packages/*\n")
	f.Add("min-release-age=7\nbefore=2026-01-01\n")
	f.Add("packageManager")
	f.Add("{\"packageManager\":\"pnpm@\"}")
	f.Add("{ truncated")
	f.Add("\x00\x1b]0;title\x07")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > nodetest.MaxFuzzInputSize {
			t.Skip("input exceeds bounded size")
		}
		dir := t.TempDir()
		for _, name := range []string{"package.json", "pnpm-workspace.yaml", ".npmrc", "yarn.lock"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(input), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}

		for _, manager := range []sdk.PackageManager{
			sdk.PackageManagerNPM,
			sdk.PackageManagerPNPM,
			sdk.PackageManagerYarn,
			sdk.PackageManagerBun,
		} {
			warnings := PackageManagerWarnings(dir, manager, LockfileFormat{File: "pnpm-lock.yaml", Version: input})
			// Parsing is deterministic for a fixed input.
			if second := PackageManagerWarnings(dir, manager, LockfileFormat{File: "pnpm-lock.yaml", Version: input}); len(second) != len(warnings) {
				t.Fatalf("non-deterministic warning count for %s: %d then %d", manager, len(warnings), len(second))
			}
			for _, warning := range warnings {
				if warning.Type != sdk.DetectorWarningPackageManager {
					t.Fatalf("unexpected warning type %q", warning.Type)
				}
				if warning.Message == "" {
					t.Fatal("warning without a message")
				}
				for _, b := range []byte(warning.Message) {
					if b == '\n' || b == '\r' {
						t.Fatalf("warning message must stay single-line: %q", warning.Message)
					}
				}
			}
		}
	})
}
