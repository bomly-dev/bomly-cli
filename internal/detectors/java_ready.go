package detectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// javaReadyTimeout bounds the `java -version` probe. It is only reached when
// a java executable exists on PATH (LookPath gates it), so a generous bound
// costs nothing in the no-java case. 5s proved too tight on loaded CI
// runners: a slow first JVM start flipped Ready to "not ready", silently
// degrading maven/gradle/sbt scans to their fallback detectors.
const javaReadyTimeout = 30 * time.Second

// JavaReady verifies that a Java runtime is available for JVM build tools. It
// returns nil when a runtime is usable and a non-nil error describing the
// reason otherwise. The probe is bound to ctx and additionally guarded by an
// internal timeout so a hung `java` cannot stall a scan.
func JavaReady(ctx context.Context, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	if _, err := system.LookPath("java"); err != nil {
		return errors.New("java executable not found on PATH")
	}

	probeCtx, cancel := context.WithTimeout(ctx, javaReadyTimeout)
	defer cancel()

	executable := "java"
	args := []string{"-version"}
	cmd := system.CommandContext(probeCtx, executable, args...)
	var diagnostics bytes.Buffer
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	logger.Debug("running Java readiness probe", logging.CommandFields(executable, args, cmd.Dir)...)
	err := cmd.Run()
	if message := strings.TrimSpace(diagnostics.String()); message != "" {
		logger.Debug("Java readiness probe diagnostics", zap.String("stderr", message))
	}
	if err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("java readiness check timed out after %s", javaReadyTimeout)
		}
		return fmt.Errorf("java runtime is unavailable: %w (diagnostic bytes: %d)", err, diagnostics.Len())
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
