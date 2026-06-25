package exit

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
	exitCodeNothingToEvaluate = 5
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

// Code converts a command error into a process exit code.
func Code(err error) int {
	if err == nil {
		return exitCodeSuccess
	}
	if coded, ok := errors.AsType[*exitError](err); ok {
		return coded.code
	}
	return exitCodeExecutionError
}

// ErrorPrefix returns the user-facing prefix that should be used when printing err.
func ErrorPrefix(err error) string {
	switch Code(err) {
	case exitCodePolicyViolation:
		return "Policy violation"
	case exitCodeNothingToEvaluate:
		// Exit 5 is a benign "no resolvable targets" outcome, not a failure;
		// print it as an informational notice rather than an error.
		return "Nothing to evaluate"
	default:
		return "Error"
	}
}

func InvalidInputError(format string, args ...any) error {
	return &exitError{code: exitCodeInvalidInput, err: fmt.Errorf(format, args...)}
}

func ResolutionFailureError(err error) error {
	return &exitError{code: exitCodeResolutionFailure, err: err}
}

// NothingToEvaluateError marks the benign "no resolvable targets" outcome —
// no subprojects/manifests were discovered for the target (with the applied
// filters). It is deliberately distinct from ResolutionFailureError (exit 3,
// a real error where a discovered subproject could not be turned into a
// graph) so CI wrappers can treat "nothing to scan" as a neutral pass without
// masking genuine resolution failures.
func NothingToEvaluateError(err error) error {
	return &exitError{code: exitCodeNothingToEvaluate, err: err}
}

// InteractiveResult wraps the error returned by tui.Run so that a missing
// terminal surfaces as an invalid-input exit (4) instead of a generic
// failure. Other errors flow through unchanged.
func InteractiveResult(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, tui.ErrNotATerminal) {
		return InvalidInputError("%v", err)
	}
	return err
}

func PolicyViolationFindings(count int) error {
	label := "findings"
	if count == 1 {
		label = "finding"
	}
	return policyViolation(fmt.Errorf("%d %s matched the configured severity threshold", count, label))
}

func policyViolation(err error) error {
	return &exitError{code: exitCodePolicyViolation, err: err}
}
