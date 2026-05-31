package main

import (
	"strings"
	"testing"
)

func TestReportMarkdown(t *testing.T) {
	got, err := reportMarkdown([]byte("Let me summarize the artifacts.\n\n# Bomly Benchmark Report  \n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# Bomly Benchmark Report\n" {
		t.Fatalf("reportMarkdown() = %q", got)
	}
}

func TestReportMarkdownRejectsMissingTitle(t *testing.T) {
	_, err := reportMarkdown([]byte("# Unexpected Report"))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error = %v, want missing title error", err)
	}
}

func TestReportMarkdownRejectsEmptyOutput(t *testing.T) {
	_, err := reportMarkdown([]byte(" \n\t"))
	if err == nil || !strings.Contains(err.Error(), "empty report") {
		t.Fatalf("error = %v, want empty report error", err)
	}
}
