package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestSeparateReport_WritesEmptyLineAfterCompletion(t *testing.T) {
	var buf bytes.Buffer
	progress := &Progress{
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

func TestSeparateReport_IgnoresIncompleteOrDisabledProgress(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &Progress{writer: &buf, enabled: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider before completion, got %q", buf.String())
		}
	})

	t.Run("disabled", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &Progress{writer: &buf, finished: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider when disabled, got %q", buf.String())
		}
	})
}

func TestFormatProgressBar(t *testing.T) {
	if got := formatProgressBar(0, 10); got != "[....................]" {
		t.Fatalf("expected empty progress bar, got %q", got)
	}
	if got := formatProgressBar(5, 10); got != "[==========..........]" {
		t.Fatalf("expected half progress bar, got %q", got)
	}
	if got := formatProgressBar(10, 10); got != "[====================]" {
		t.Fatalf("expected full progress bar, got %q", got)
	}
}

func TestStageShowsBarAndPercent(t *testing.T) {
	var buf bytes.Buffer
	progress := &Progress{writer: &buf, enabled: true}

	progress.setStageProgress("Detected Dependencies", 3, 10)

	rendered := buf.String()
	if !strings.Contains(rendered, "[======..............]") {
		t.Fatalf("expected rendered progress bar, got %q", rendered)
	}
	if !strings.Contains(rendered, "30%") {
		t.Fatalf("expected rendered percentage, got %q", rendered)
	}
}
