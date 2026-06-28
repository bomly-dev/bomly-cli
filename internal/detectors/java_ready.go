package detectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/system"
)

const javaReadyTimeout = 5 * time.Second

// JavaReady verifies that a Java runtime is available for JVM build tools. It
// returns nil when a runtime is usable and a non-nil error describing the
// reason otherwise. The probe is bound to ctx and additionally guarded by an
// internal timeout so a hung `java` cannot stall a scan.
func JavaReady(ctx context.Context) error {
	if _, err := system.LookPath("java"); err != nil {
		return errors.New("java executable not found on PATH")
	}

	probeCtx, cancel := context.WithTimeout(ctx, javaReadyTimeout)
	defer cancel()

	cmd := system.CommandContext(probeCtx, "java", "-version")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("java readiness check timed out after %s", javaReadyTimeout)
		}
		message := strings.TrimSpace(output.String())
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("java runtime is unavailable: %s", message)
	}
	return nil
}

// CommandNotReadyError returns a compact readiness error for a missing tool, or
// nil when err is nil.
func CommandNotReadyError(name string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%s executable not found on PATH", name)
	}
	return fmt.Errorf("resolve %s executable: %w", name, err)
}
