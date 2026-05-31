package main

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	summaryPath = ".benchmark-runs/latest/benchmark-summary.json"
	promptPath  = "docs/prompts/bomly-benchmark-report.prompt.md"
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
	cmd := exec.Command("copilot", "-p", string(prompt), "--allow-tool=write", "--no-ask-user")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		exitf("run copilot benchmark report: %v", err)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
