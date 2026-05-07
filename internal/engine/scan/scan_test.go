package scan

import (
	"context"
	"testing"
)

func TestRunRejectsNilPipeline(t *testing.T) {
	if _, err := Run(context.Background(), nil, Request{}); err == nil {
		t.Fatal("expected nil pipeline error")
	}
}
