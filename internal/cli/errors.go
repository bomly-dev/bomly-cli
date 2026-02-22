package cli

import (
	"errors"
	"fmt"
)

const (
	exitCodeSuccess            = 0
	exitCodeExecutionError     = 1
	exitCodeInvalidInput       = 2
	exitCodeResolutionFailure  = 3
	exitCodePolicyViolation    = 4
	exitCodeVerificationFailed = 5
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	return e.err.Error()
}

func (e *exitError) Unwrap() error {
	return e.err
}

// ExitCode converts a command error into a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return exitCodeSuccess
	}
	var coded *exitError
	if errors.As(err, &coded) {
		return coded.code
	}
	return exitCodeExecutionError
}

func invalidInputf(format string, args ...any) error {
	return &exitError{code: exitCodeInvalidInput, err: fmt.Errorf(format, args...)}
}

func resolutionFailure(err error) error {
	return &exitError{code: exitCodeResolutionFailure, err: err}
}
