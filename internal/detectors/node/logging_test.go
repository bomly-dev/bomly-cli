package node

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestInstallLogsReproducibleCommandAndDebugStderr(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	t.Setenv("BOMLY_NODE_INSTALL_HELPER", "1")
	workingDir := t.TempDir()
	args := []string{
		"--token", "token-secret",
		"--registry=https://user:url-secret@example.test/packages",
		"--color=always",
	}
	var visibleStderr bytes.Buffer

	err = (BaseDetector{Logger: logger, WorkingDir: workingDir}).Install(
		context.Background(),
		sdk.DetectionRequest{InstallArgs: args, Stderr: &visibleStderr, Verbose: true},
		executable,
		[]string{"-test.run=TestNodeInstallLoggingHelper", "--"},
		"test detector",
	)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !strings.Contains(visibleStderr.String(), "stderr-secret") {
		t.Fatalf("subprocess stderr was not mirrored in debug mode: %q", visibleStderr.String())
	}

	entries := observed.FilterMessage("running detector install-first").All()
	if len(entries) != 1 {
		t.Fatalf("command logs = %#v", observed.All())
	}
	fields := entries[0].ContextMap()
	rendered := fmt.Sprint(fields)
	for _, secret := range []string{"token-secret", "url-secret", "stderr-secret", "user"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("command log retained %q: %s", secret, rendered)
		}
	}
	if fields["executable"] != executable || fields["working_dir"] != workingDir ||
		!strings.Contains(rendered, "--color=always") ||
		!strings.Contains(rendered, "[REDACTED]") {
		t.Fatalf("command log lost reproducible fields: %#v", fields)
	}
}

func TestNodeInstallLoggingHelper(t *testing.T) {
	if os.Getenv("BOMLY_NODE_INSTALL_HELPER") != "1" {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "stderr-secret")
}
