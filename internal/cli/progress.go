package cli

import (
	"github.com/bomly-dev/bomly-cli/internal/progress"
)

// Type aliases keep the cli package referring to commandProgress / progressChild
// while the implementation lives in internal/progress.
type (
	commandProgress = progress.Progress
	progressChild   = progress.Child
)

// Visual marks re-exported so cli code can build progressChild values without
// importing the progress package directly.
const (
	progressCheckMark   = progress.CheckMark
	progressCrossMark   = progress.CrossMark
	progressWarningMark = progress.WarningMark
)

// newCommandProgress constructs a Progress sourcing its writer + TTY-detection
// from the CLI's commandStreams.
func newCommandProgress(streams commandStreams, label string) *commandProgress {
	return progress.New(streams.notificationWriter(), streams.canRenderProgress(), label)
}
