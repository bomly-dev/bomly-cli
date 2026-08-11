//go:build smoke

package smoke

import (
	"strings"
	"testing"
)

// minSupportedSDKVersion is the oldest github.com/bomly-dev/bomly-sdk release
// whose plugin binaries the current Bomly binary must keep loading and
// running. Bump it only when a wire-protocol major version is retired.
const minSupportedSDKVersion = "v0.1.0"

// TestPluginMinVersionWireCompat proves wire compatibility with old plugin
// binaries: it builds the example detector fixture against the OLDEST
// supported SDK release (not the pinned one), installs and enables it with
// the current binary, and runs a scan through it. A plugin author who built
// and shipped a binary against minSupportedSDKVersion must not need to
// recompile when users upgrade Bomly.
func TestPluginMinVersionWireCompat(t *testing.T) {
	requireTool(t, "go")

	plugin := buildExamplePluginWithSDK(t, minSupportedSDKVersion)
	projectDir := createExamplePluginProject(t)
	env := pluginWorkflowEnv(t)

	stdout, stderr, code := runBomlyWithEnv(t, env, "plugin", "install", plugin.BinaryPath, "--dev")
	if code != 0 {
		t.Fatalf("min-version plugin install --dev exited %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "Installed "+plugin.ID+"@0.0.0-dev") {
		t.Fatalf("unexpected min-version install output:\n%s", stdout)
	}
	if _, enableStderr, enableCode := runBomlyWithEnv(t, env, "plugin", "enable", plugin.ID); enableCode != 0 {
		t.Fatalf("min-version plugin enable exited %d\nstderr:\n%s", enableCode, enableStderr)
	}

	scanStdout, scanStderr, scanCode := runBomlyWithEnv(t, env,
		"scan",
		"--path", projectDir,
		"--detectors", plugin.ID,
		"--format", "json",
	)
	if scanCode != 0 {
		t.Fatalf("min-version plugin scan exited %d\nstderr:\n%s", scanCode, scanStderr)
	}
	// The fixture detector reports the scanned module itself as a package, so
	// the module path landing in the scan output proves the old-SDK plugin
	// binary produced the dependency graph over the current wire protocol.
	if !strings.Contains(scanStdout, "example.com/plugin-smoke") {
		t.Fatalf("scan output does not contain the fixture module detected by the %s-built plugin:\n%s",
			minSupportedSDKVersion, scanStdout)
	}
}
