package cli

import (
	"errors"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/tui"
)

const (
	exitCodeSuccess           = 0
	exitCodeExecutionError    = 1
	exitCodePolicyViolation   = 2
	exitCodeResolutionFailure = 3
	exitCodeInvalidInput      = 4
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

// ErrorPrefix returns the user-facing prefix that should be used when printing err.
func ErrorPrefix(err error) string {
	switch ExitCode(err) {
	case exitCodePolicyViolation:
		return "Policy violation"
	default:
		return "Error"
	}
}

func invalidInputf(format string, args ...any) error {
	return &exitError{code: exitCodeInvalidInput, err: fmt.Errorf(format, args...)}
}

func resolutionFailure(err error) error {
	return &exitError{code: exitCodeResolutionFailure, err: err}
}

func policyViolation(err error) error {
	return &exitError{code: exitCodePolicyViolation, err: err}
}

// interactiveResult wraps the error returned by tui.Run so that a missing
// terminal surfaces as an invalid-input exit (4) instead of a generic
// failure. Other errors flow through unchanged.
func interactiveResult(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, tui.ErrNotATerminal) {
		return invalidInputf("%v", err)
	}
	return err
}

func policyViolationFindings(count int) error {
	label := "findings"
	if count == 1 {
		label = "finding"
	}
	return policyViolation(fmt.Errorf("%d %s matched the configured severity threshold", count, label))
}
