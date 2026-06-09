package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	write := flag.Bool("w", false, "rewrite tracked Go files with gofmt")
	flag.Parse()

	files, err := trackedGoFiles()
	if err != nil {
		exitf("list tracked go files: %v", err)
	}
	if len(files) == 0 {
		return
	}

	if *write {
		if err := runGofmt("-w", files); err != nil {
			exitf("run gofmt -w: %v", err)
		}
		return
	}

	out, err := runGofmtWithOutput("-l", files)
	if err != nil {
		exitf("run gofmt -l: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		_, _ = fmt.Fprint(os.Stderr, out)
		os.Exit(1)
	}
}

func trackedGoFiles() ([]string, error) {
	cmd := exec.Command("git", "ls-files", "*.go")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}

	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := os.Stat(line); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("stat tracked go file %q: %w", line, err)
		}
		files = append(files, line)
	}
	return files, nil
}

func runGofmt(mode string, files []string) error {
	_, err := runGofmtWithOutput(mode, files)
	return err
}

func runGofmtWithOutput(mode string, files []string) (string, error) {
	args := make([]string, 0, len(files)+1)
	args = append(args, mode)
	args = append(args, files...)

	cmd := exec.Command("gofmt", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), err
	}
	return stdout.String(), nil
}

func exitf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
