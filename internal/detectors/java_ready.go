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

// JavaReady verifies that a Java runtime is available for JVM build tools.
func JavaReady() (bool, string) {
	if _, err := system.LookPath("java"); err != nil {
		return false, "java executable not found on PATH"
	}

	ctx, cancel := context.WithTimeout(context.Background(), javaReadyTimeout)
	defer cancel()

	cmd := system.CommandContext(ctx, "java", "-version")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Sprintf("java readiness check timed out after %s", javaReadyTimeout)
		}
		message := strings.TrimSpace(output.String())
		if message == "" {
			message = err.Error()
		}
		return false, "java runtime is unavailable: " + message
	}
	return true, ""
}

// CommandReadyReason returns a compact readiness message for missing tools.
func CommandReadyReason(name string, err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Sprintf("%s executable not found on PATH", name)
	}
	return fmt.Sprintf("resolve %s executable: %v", name, err)
}
