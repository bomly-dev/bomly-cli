package govulncheck

import (
	"errors"
	"fmt"
	"testing"
)

// exitCode3Error mimics x/vuln's unexported exitCodeError: an error
// carrying ExitCode() int that scan.Cmd.Wait wraps.
type exitCode3Error struct{ code int }

func (e exitCode3Error) Error() string { return fmt.Sprintf("govulncheck exit code %d", e.code) }

func (e exitCode3Error) ExitCode() int { return e.code }

func TestIsVulnsFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "bare exit status 3", err: errors.New("exit status 3"), want: true},
		{name: "unrelated", err: errors.New("go: no such tool"), want: false},
		{name: "exit code 3 sentinel", err: exitCode3Error{code: 3}, want: true},
		{name: "wrapped exit code 3", err: fmt.Errorf("govulncheck: %w", exitCode3Error{code: 3}), want: true},
		{name: "doubly wrapped exit code 3", err: fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", exitCode3Error{code: 3})), want: true},
		{name: "wrapped exit code 1", err: fmt.Errorf("govulncheck: %w", exitCode3Error{code: 1}), want: false},
		{name: "wrapped exec message", err: fmt.Errorf("govulncheck: %w", errors.New("exit status 3")), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVulnsFound(tc.err); got != tc.want {
				t.Errorf("isVulnsFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
