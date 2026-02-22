package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMain_PrintsCommandErrorsToStderr(t *testing.T) {
	if os.Getenv("GO_WANT_BOMLY_HELPER_PROCESS") == "1" {
		os.Args = []string{"bomly", "explain"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMain_PrintsCommandErrorsToStderr$", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_BOMLY_HELPER_PROCESS=1")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected helper process to exit with an error")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %d; stderr=%s", exitErr.ExitCode(), stderr.String())
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Error: explain expects exactly one package argument") {
		t.Fatalf("expected formatted error on stderr, got %q", stderr.String())
	}
}
