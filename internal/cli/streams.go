package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/term"
)

const commandStdoutCaptureTimeout = time.Second

type commandStreams struct {
	stdout    io.Writer
	stderr    io.Writer
	quiet     bool
	verbosity int
}

func newCommandStreams(cmd *cobra.Command, quiet bool, verbosity int) commandStreams {
	if cmd == nil {
		return commandStreams{stdout: io.Discard, stderr: io.Discard, quiet: quiet, verbosity: verbosity}
	}
	return commandStreams{
		stdout:    cmd.OutOrStdout(),
		stderr:    cmd.ErrOrStderr(),
		quiet:     quiet,
		verbosity: verbosity,
	}
}

func (s commandStreams) reportWriter() io.Writer {
	if s.stdout == nil {
		return io.Discard
	}
	return s.stdout
}

func (s commandStreams) notificationWriter() io.Writer {
	if s.quiet || s.stderr == nil {
		return io.Discard
	}
	return s.stderr
}

func (s commandStreams) interactiveWriter() io.Writer {
	if s.stderr == nil {
		return io.Discard
	}
	return s.stderr
}

func (s commandStreams) warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(s.notificationWriter(), format+"\n", args...)
}

func (s commandStreams) canRenderProgress() bool {
	if s.quiet || s.verbosity > 0 || s.stderr == nil {
		return false
	}
	file, ok := s.stderr.(*os.File)
	if !ok || file == nil {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func (s commandStreams) captureStdoutToDebugLog(logger *zap.Logger) func() {
	if logger == nil {
		logger = zap.NewNop()
	}

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		logger.Debug("stdout capture unavailable", zap.Error(err))
		return func() {}
	}

	os.Stdout = w
	done := make(chan struct{}, 1)

	go func() {
		defer func() {
			_ = r.Close()
			done <- struct{}{}
		}()

		buf := make([]byte, 1024)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				captured := strings.TrimSpace(string(buf[:n]))
				if captured != "" {
					logger.Debug("captured stdout output", zap.String("output", captured))
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	return func() {
		_ = w.Close()
		select {
		case <-done:
		case <-time.After(commandStdoutCaptureTimeout):
			logger.Debug("stdout capture timed out", zap.Duration("timeout", commandStdoutCaptureTimeout))
		}
		os.Stdout = original
	}
}
