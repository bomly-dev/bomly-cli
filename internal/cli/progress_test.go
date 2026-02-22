package cli

import (
	"bytes"
	"testing"
)

func TestCommandProgressSeparateReport_WritesEmptyLineAfterCompletion(t *testing.T) {
	var buf bytes.Buffer
	progress := &commandProgress{
		writer:   &buf,
		enabled:  true,
		finished: true,
	}

	progress.SeparateReport()
	progress.SeparateReport()

	expected := "\n"
	if buf.String() != expected {
		t.Fatalf("expected divider after completion, got %q", buf.String())
	}
}

func TestCommandProgressSeparateReport_IgnoresIncompleteOrDisabledProgress(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &commandProgress{writer: &buf, enabled: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider before completion, got %q", buf.String())
		}
	})

	t.Run("disabled", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &commandProgress{writer: &buf, finished: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider when disabled, got %q", buf.String())
		}
	})
}
