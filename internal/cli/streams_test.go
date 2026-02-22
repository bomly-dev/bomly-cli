package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestCommandStreamsNotificationWriter_RespectsQuiet(t *testing.T) {
	cmd := &cobra.Command{Use: "bomly"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	noisy := newCommandStreams(cmd, false, 0)
	if _, err := io.WriteString(noisy.notificationWriter(), "warn\n"); err != nil {
		t.Fatalf("write notification: %v", err)
	}
	if got := stderr.String(); !strings.Contains(got, "warn") {
		t.Fatalf("expected stderr notification, got %q", got)
	}

	stderr.Reset()
	quiet := newCommandStreams(cmd, true, 0)
	if _, err := io.WriteString(quiet.notificationWriter(), "hidden\n"); err != nil {
		t.Fatalf("write quiet notification: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected quiet notification writer to suppress output, got %q", stderr.String())
	}
}

func TestCommandStreamsCaptureStdoutToDebugLog(t *testing.T) {
	originalStdout := os.Stdout
	defer func() { os.Stdout = originalStdout }()

	cmd := &cobra.Command{Use: "bomly"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&stderr), zap.DebugLevel)
	logger := zap.New(core)
	streams := newCommandStreams(cmd, false, 0)
	restore := streams.captureStdoutToDebugLog(logger)
	_, _ = os.Stdout.WriteString("unexpected stdout\n")
	restore()

	if stdout.Len() != 0 {
		t.Fatalf("expected captured stdout not to reach report writer, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "captured stdout output") || !strings.Contains(stderr.String(), "unexpected stdout") {
		t.Fatalf("expected debug log for captured stdout, got %q", stderr.String())
	}
}

func TestCommandStreamsInteractiveWriter_UsesStderr(t *testing.T) {
	cmd := &cobra.Command{Use: "bomly"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	streams := newCommandStreams(cmd, false, 0)
	if _, err := io.WriteString(streams.interactiveWriter(), "ui\n"); err != nil {
		t.Fatalf("write interactive output: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected interactive output to stay off stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "ui") {
		t.Fatalf("expected interactive output on stderr, got %q", stderr.String())
	}
}
