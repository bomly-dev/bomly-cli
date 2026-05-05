package cli

import (
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func commandLogger(cmd *cobra.Command, options *globalOptions, name string) *zap.Logger {
	current := options.current()
	// In default mode (no verbosity flags), suppress log output so only the
	// progress UI is visible. In verbose mode, the logger replaces the UI.
	// Quiet mode suppresses everything except errors.
	if current.Quiet || current.Verbosity == 0 {
		return zap.NewNop().Named(name)
	}
	return logging.NewConsole(cmd.ErrOrStderr(), current.Verbosity, false).Named(name)
}
