package render

import (
	"strconv"
	"strings"
	"testing"
)

// clearLogoEnv isolates logo gating tests from the ambient environment (CI
// runners set CI=true, which would flip animate-expected cases).
func clearLogoEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"NO_COLOR", "BOMLY_NO_ANIMATION", "CI", "BOMLY_QUIET"} {
		t.Setenv(name, "")
	}
}

func frameLines(t *testing.T, frame string) []string {
	t.Helper()
	plain := StripANSI(frame)
	trimmed := strings.TrimSuffix(plain, "\n")
	lines := strings.Split(trimmed, "\n")
	for idx, line := range lines {
		lines[idx] = strings.TrimPrefix(line, "\r")
	}
	return lines
}

// forEachLogoVariant runs the assertion against every animation variant.
func forEachLogoVariant(t *testing.T, assert func(t *testing.T, frames []string)) {
	t.Helper()
	if len(logoVariantNames) != len(logoVariantFrames) {
		t.Fatalf("variant name list has %d entries, frame map has %d", len(logoVariantNames), len(logoVariantFrames))
	}
	for _, name := range logoVariantNames {
		gen, ok := logoVariantFrames[name]
		if !ok {
			t.Fatalf("variant %q has no frame generator", name)
		}
		t.Run(name, func(t *testing.T) {
			assert(t, gen())
		})
	}
}

func TestBomlyLogoFramesCountAndShape(t *testing.T) {
	forEachLogoVariant(t, func(t *testing.T, frames []string) {
		if len(frames) != logoFrameCount {
			t.Fatalf("expected %d animation frames, got %d", logoFrameCount, len(frames))
		}
		artWidth := len([]rune(bomlyLogoArt()[0]))
		for idx, frame := range frames {
			lines := frameLines(t, frame)
			if len(lines) != bomlyLogoFrameLineCount() {
				t.Fatalf("frame %d: expected %d lines, got %d:\n%s", idx, bomlyLogoFrameLineCount(), len(lines), frame)
			}
			for row, line := range lines[:len(bomlyLogoArt())] {
				if got := len([]rune(line)); got > artWidth {
					t.Fatalf("frame %d row %d: width %d exceeds art width %d", idx, row, got, artWidth)
				}
			}
		}
	})
}

func TestBomlyLogoFramesFirstFrameIsPartial(t *testing.T) {
	forEachLogoVariant(t, func(t *testing.T, frames []string) {
		plain := StripANSI(frames[0])
		if strings.Contains(plain, bomlyLogoArt()[0]) {
			t.Fatalf("expected first frame to be a partial reveal, got full art line:\n%s", plain)
		}
		if strings.Contains(plain, bomlyLogoTagline) {
			t.Fatalf("expected first frame to omit the tagline, got:\n%s", plain)
		}
	})
}

func TestBomlyLogoFramesFinalFrameIsArt(t *testing.T) {
	forEachLogoVariant(t, func(t *testing.T, frames []string) {
		plain := StripANSI(frames[len(frames)-1])
		for _, want := range bomlyLogoArt() {
			if !strings.Contains(plain, strings.TrimRight(want, " ")) {
				t.Fatalf("expected final frame to contain %q, got:\n%s", want, plain)
			}
		}
		if !strings.Contains(plain, bomlyLogoTagline) {
			t.Fatalf("expected final frame to contain tagline %q, got:\n%s", bomlyLogoTagline, plain)
		}
	})
}

func TestBomlyLogoFramesResolveBeforeFinale(t *testing.T) {
	forEachLogoVariant(t, func(t *testing.T, frames []string) {
		plain := StripANSI(frames[logoRevealFrameCount-1])
		for _, want := range bomlyLogoArt() {
			if !strings.Contains(plain, strings.TrimRight(want, " ")) {
				t.Fatalf("expected last reveal frame to already contain %q (no pop into the finale), got:\n%s", want, plain)
			}
		}
	})
}

func TestBomlyLogoFramesDeterministic(t *testing.T) {
	for _, name := range logoVariantNames {
		t.Run(name, func(t *testing.T) {
			gen := logoVariantFrames[name]
			first := gen()
			second := gen()
			if len(first) != len(second) {
				t.Fatalf("frame counts differ: %d vs %d", len(first), len(second))
			}
			for idx := range first {
				if first[idx] != second[idx] {
					t.Fatalf("frame %d differs between generations", idx)
				}
			}
		})
	}
}

func TestBomlyLogoFramesMonotonicReveal(t *testing.T) {
	forEachLogoVariant(t, func(t *testing.T, frames []string) {
		prev := -1
		for idx, frame := range frames {
			count := 0
			for _, r := range StripANSI(frame) {
				if r != ' ' && r != '\n' && r != '\r' {
					count++
				}
			}
			if count < prev {
				t.Fatalf("frame %d: materialized cell count %d dropped below previous %d", idx, count, prev)
			}
			prev = count
		}
	})
}

func TestBomlyLogoFrameLineCount(t *testing.T) {
	if got, want := bomlyLogoFrameLineCount(), len(bomlyLogoArt())+2; got != want {
		t.Fatalf("bomlyLogoFrameLineCount() = %d, want %d", got, want)
	}
}

func TestStartupLogoMode(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want logoMode
	}{
		{name: "default animates", env: nil, want: logoAnimate},
		{name: "NO_COLOR plain static", env: map[string]string{"NO_COLOR": "1"}, want: logoStaticPlain},
		{name: "NO_COLOR wins over no-animation", env: map[string]string{"NO_COLOR": "1", "BOMLY_NO_ANIMATION": "1"}, want: logoStaticPlain},
		{name: "no-animation colored static", env: map[string]string{"BOMLY_NO_ANIMATION": "1"}, want: logoStaticColor},
		{name: "no-animation zero animates", env: map[string]string{"BOMLY_NO_ANIMATION": "0"}, want: logoAnimate},
		{name: "no-animation false animates", env: map[string]string{"BOMLY_NO_ANIMATION": "FALSE"}, want: logoAnimate},
		{name: "CI colored static", env: map[string]string{"CI": "true"}, want: logoStaticColor},
		{name: "CI zero animates", env: map[string]string{"CI": "0"}, want: logoAnimate},
		{name: "quiet colored static", env: map[string]string{"BOMLY_QUIET": "1"}, want: logoStaticColor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearLogoEnv(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			if got := startupLogoMode(); got != tc.want {
				t.Fatalf("startupLogoMode() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSelectedLogoFrames(t *testing.T) {
	t.Run("pinned variant", func(t *testing.T) {
		t.Setenv("BOMLY_LOGO", "rain")
		got := selectedLogoFrames()
		want := logoRainFrames()
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatal("expected BOMLY_LOGO=rain to select the rain variant")
		}
	})
	t.Run("pin is case-insensitive", func(t *testing.T) {
		t.Setenv("BOMLY_LOGO", "GLITCH")
		got := selectedLogoFrames()
		want := logoGlitchFrames()
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatal("expected BOMLY_LOGO=GLITCH to select the glitch variant")
		}
	})
	for _, value := range []string{"", "unknown-variant"} {
		t.Run("fallback for "+strconv.Quote(value), func(t *testing.T) {
			t.Setenv("BOMLY_LOGO", value)
			if got := selectedLogoFrames(); len(got) != logoFrameCount {
				t.Fatalf("expected a valid random variant, got %d frames", len(got))
			}
		})
	}
}

func TestBomlyLogoStatic(t *testing.T) {
	plain := bomlyLogoStatic(false)
	if strings.Contains(plain, "\x1b") {
		t.Fatalf("expected plain static logo to contain no escape sequences, got:\n%q", plain)
	}
	colored := bomlyLogoStatic(true)
	if !strings.Contains(colored, "\x1b") {
		t.Fatal("expected colored static logo to contain escape sequences")
	}
	if got := StripANSI(colored); got != plain {
		t.Fatalf("colored static logo strips to:\n%q\nwant:\n%q", got, plain)
	}
	for _, want := range append(bomlyLogoArt(), bomlyLogoTagline) {
		if !strings.Contains(plain, want) {
			t.Fatalf("expected static logo to contain %q", want)
		}
	}
}
