package logging

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestFormatDuration(t *testing.T) {
	if got := FormatDuration(1450 * time.Millisecond); got != "1.5s" {
		t.Fatalf("FormatDuration() = %q, want %q", got, "1.5s")
	}
	if got := FormatDuration(95 * time.Millisecond); got != "100ms" {
		t.Fatalf("FormatDuration() = %q, want %q", got, "100ms")
	}
}

func TestNewConsoleAndCommandStderr(t *testing.T) {
	var stderr bytes.Buffer
	logger := NewConsole(&stderr, 1, false)
	logger.Info("scan complete", zap.String("project", "demo"))
	if !strings.Contains(stderr.String(), "scan complete") || !strings.Contains(stderr.String(), `"project": "demo"`) {
		t.Fatalf("expected pretty console output, got %q", stderr.String())
	}

	var visible bytes.Buffer
	writer := NewCommandStderr(&visible, true)
	if _, err := writer.Write([]byte("warn: noisy stderr\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := writer.String(); got != "warn: noisy stderr" {
		t.Fatalf("String() = %q", got)
	}
	if !strings.Contains(visible.String(), "warn: noisy stderr") {
		t.Fatalf("expected visible writer mirroring, got %q", visible.String())
	}
}

func TestCommandStderrNilAndHidden(t *testing.T) {
	var writer *CommandStderr
	if _, err := writer.Write([]byte("ignored")); err != nil {
		t.Fatalf("nil Write() error = %v", err)
	}

	var visible bytes.Buffer
	hidden := NewCommandStderr(&visible, false)
	if _, err := hidden.Write([]byte("secret\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if visible.Len() != 0 {
		t.Fatalf("expected hidden writer not to mirror output, got %q", visible.String())
	}
}

func TestNewConsoleQuietSuppressesNonErrors(t *testing.T) {
	var stderr bytes.Buffer
	logger := NewConsole(&stderr, 1, true)
	logger.Info("hidden info")
	logger.Warn("hidden warn")
	logger.Error("visible error")
	output := stderr.String()
	if strings.Contains(output, "hidden info") || strings.Contains(output, "hidden warn") {
		t.Fatalf("expected quiet logger to suppress non-errors, got %q", output)
	}
	if !strings.Contains(output, "visible error") {
		t.Fatalf("expected quiet logger to keep errors, got %q", output)
	}
}
