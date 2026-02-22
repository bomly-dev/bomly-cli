package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"

	"github.com/bomly/bomly-cli/pkg/system"
)

// RunOptions customizes plugin subprocess execution.
type RunOptions struct {
	WorkingDir string
	ConfigPath string
	Env        []string
}

// Run executes a plugin command with stdio passthrough.
func Run(path, subcommand string, args []string, coreVersion string, stdout, stderr io.Writer, stdin io.Reader) (int, error) {
	return RunWithOptions(path, subcommand, args, coreVersion, stdout, stderr, stdin, RunOptions{})
}

// RunWithOptions executes a plugin command with stdio passthrough and execution options.
func RunWithOptions(path, subcommand string, args []string, coreVersion string, stdout, stderr io.Writer, stdin io.Reader, opts RunOptions) (int, error) {
	callArgs := append([]string{subcommand}, args...)
	cmd := system.Command(path, callArgs...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = stdin

	workingDir := opts.WorkingDir
	if workingDir == "" {
		cwd, err := system.Getwd()
		if err != nil {
			return 1, fmt.Errorf("resolve cwd: %w", err)
		}
		workingDir = cwd
	}
	cmd.Dir = workingDir

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = filepath.Join(workingDir, ".bomly.yaml")
	}

	cmd.Env = append(system.Environ(),
		"BOMLY_PROTOCOL=v1",
		"BOMLY_CORE_VERSION="+coreVersion,
		"BOMLY_CWD="+workingDir,
		"BOMLY_CONFIG="+configPath,
	)
	cmd.Env = append(cmd.Env, opts.Env...)

	runErr := cmd.Run()
	if runErr == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}

	return 1, fmt.Errorf("execute plugin %s: %w", path, runErr)
}

// RunWithEnvelope executes a plugin stage using the JSON envelope protocol.
// It writes the envelope to stdin, reads the envelope from stdout, and returns
// the parsed response envelope.
func RunWithEnvelope(path, subcommand string, stage string, input any, stderr io.Writer, coreVersion string, opts RunOptions) (Envelope, error) {
	envBytes, err := NewEnvelope(stage, input)
	if err != nil {
		return Envelope{}, fmt.Errorf("encode envelope: %w", err)
	}

	var stdout bytes.Buffer
	exitCode, err := RunWithOptions(path, subcommand, nil, coreVersion, &stdout, stderr, bytes.NewReader(envBytes), opts)
	if err != nil {
		return Envelope{}, err
	}
	if exitCode != 0 {
		return Envelope{}, fmt.Errorf("plugin %s %s exited with code %d", path, subcommand, exitCode)
	}

	outBytes := stdout.Bytes()
	env, parseErr := ParseEnvelope(outBytes)
	if parseErr != nil {
		return Envelope{}, fmt.Errorf("invalid envelope response: %w", parseErr)
	}
	return env, nil
}

// DecodePayload unmarshals the envelope payload into the given type.
func DecodePayload[T any](env Envelope) (T, error) {
	var result T
	if err := json.Unmarshal(env.Payload, &result); err != nil {
		return result, fmt.Errorf("decode %s payload: %w", env.Stage, err)
	}
	return result, nil
}
