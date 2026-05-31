package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

const (
	summaryPath = ".benchmark-runs/latest/benchmark-summary.json"
	promptPath  = "docs/prompts/bomly-benchmark-report.prompt.md"
	reportPath  = ".benchmark-runs/latest/benchmark-report.md"
	reportTitle = "# Bomly Benchmark Report"
)

func main() {
	if _, err := os.Stat(summaryPath); err != nil {
		exitf("benchmark report requires %s: %v", summaryPath, err)
	}
	if _, err := exec.LookPath("copilot"); err != nil {
		exitf("benchmark report requires copilot on PATH: %v", err)
	}
	prompt, err := os.ReadFile(promptPath)
	if err != nil {
		exitf("read benchmark report prompt: %v", err)
	}
	cmd := exec.Command(
		"copilot",
		"--no-ask-user",
		"--no-custom-instructions",
		"--disable-builtin-mcps",
		"--deny-tool=shell",
		"--deny-tool=write",
		"--deny-tool=url",
		"-p",
		string(prompt),
	)
	var report bytes.Buffer
	cmd.Stdout = &report
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		exitf("run copilot benchmark report: %v", err)
	}
	content, err := reportMarkdown(report.Bytes())
	if err != nil {
		exitf("render benchmark report: %v", err)
	}
	if err := os.WriteFile(reportPath, content, 0o644); err != nil {
		exitf("write benchmark report: %v", err)
	}
	fmt.Printf("wrote %s\n", reportPath)
}

func reportMarkdown(content []byte) ([]byte, error) {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return nil, fmt.Errorf("copilot returned an empty report")
	}
	start := bytes.Index(content, []byte(reportTitle))
	if start < 0 {
		return nil, fmt.Errorf("copilot report is missing %q", reportTitle)
	}
	content = bytes.TrimSpace(content[start:])
	return append(content, '\n'), nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
