package detectors

import (
	"context"
	"testing"
	"time"
)

func TestBuildToolContextSetsDeadline(t *testing.T) {
	ctx, cancel := BuildToolContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("BuildToolContext returned a context without a deadline")
	}
	if remaining := time.Until(deadline); remaining > BuildToolTimeout {
		t.Fatalf("deadline %s exceeds BuildToolTimeout %s", remaining, BuildToolTimeout)
	}
}

func TestBuildToolContextKeepsTighterParentDeadline(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer parentCancel()

	ctx, cancel := BuildToolContext(parent)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("BuildToolContext returned a context without a deadline")
	}
	if time.Until(deadline) > time.Millisecond {
		t.Fatal("BuildToolContext loosened the parent context's tighter deadline")
	}
}
