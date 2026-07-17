package detectors

import (
	"context"
	"time"
)

// BuildToolTimeout bounds a single build-tool invocation (mvn, gradle, sbt).
// These commands resolve dependency graphs over the network, and a stalled
// remote (observed twice with Maven Central) would otherwise hang the scan
// indefinitely because the pipeline context carries no deadline. The bound is
// deliberately generous — healthy resolutions finish in seconds to a few
// minutes even on cold caches — so hitting it means the tool is stuck, not
// slow.
const BuildToolTimeout = 10 * time.Minute

// BuildToolContext derives a context for one build-tool invocation, bounded
// by BuildToolTimeout on top of whatever deadline ctx already carries.
func BuildToolContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, BuildToolTimeout)
}
