package render

import (
	"strings"
	"testing"
)

func TestBomlyLogoFrames(t *testing.T) {
	frames := bomlyLogoFrames()
	if len(frames) < 8 {
		t.Fatalf("expected multiple animation frames, got %d", len(frames))
	}
	for _, frame := range frames {
		plain := StripANSI(frame)
		for _, want := range []string{
			"██████╗",
			"Analyze Your Software DNA.",
		} {
			if !strings.Contains(plain, want) {
				t.Fatalf("expected frame to contain %q, got:\n%s", want, plain)
			}
		}
	}
}

func TestBomlyLogoFrameLineCount(t *testing.T) {
	if got, want := bomlyLogoFrameLineCount(), len(bomlyLogoArt())+2; got != want {
		t.Fatalf("bomlyLogoFrameLineCount() = %d, want %d", got, want)
	}
}
