package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSeparateReport_WritesEmptyLineAfterCompletion(t *testing.T) {
	var buf bytes.Buffer
	progress := &Progress{
		writer:   &buf,
		enabled:  true,
		finished: true,
	}

	progress.SeparateReport()
	progress.SeparateReport()

	expected := "\n"
	if buf.String() != expected {
		t.Fatalf("expected divider after completion, got %q", buf.String())
	}
}

func TestSeparateReport_IgnoresIncompleteOrDisabledProgress(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &Progress{writer: &buf, enabled: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider before completion, got %q", buf.String())
		}
	})

	t.Run("disabled", func(t *testing.T) {
		var buf bytes.Buffer
		progress := &Progress{writer: &buf, finished: true}

		progress.SeparateReport()

		if buf.Len() != 0 {
			t.Fatalf("expected no divider when disabled, got %q", buf.String())
		}
	})
}

// drainAfter waits long enough for the ticker goroutine to perform at least
// one frame draw, so test buffers reflect the latest state.
func drainAfter() {
	time.Sleep(spin.FPS * 3)
}

func TestStepRendersBubblesBarWithPercent(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.StartStage("Detecting dependencies", 10)
	p.AdvanceStage("Detecting dependencies", 3, 10)
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Detecting dependencies") {
		t.Fatalf("expected active label, got %q", out)
	}
	if !strings.Contains(out, " 30%") {
		t.Fatalf("expected manually-rendered percentage, got %q", out)
	}
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("expected ANSI escape sequences (color/cursor), got %q", out)
	}
}

func TestDetailUpdatesActiveHint(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.StartStage("Detecting dependencies", 5)
	p.Detail("Detecting dependencies", "go-detector - root (gomod)")
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Detecting dependencies") {
		t.Fatalf("expected step label in render, got %q", out)
	}
	if !strings.Contains(out, "go-detector - root (gomod)") {
		t.Fatalf("expected detail text in render, got %q", out)
	}
}

func TestMultiLineRedrawShape(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.Start("a", "Stage A")
	p.Start("b", "Stage B")
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Stage A") || !strings.Contains(out, "Stage B") {
		t.Fatalf("expected both active labels in render, got %q", out)
	}
	// Two active lines means the next redraw should issue a cursor-up of 2
	// somewhere in the stream, AND have erased two lines.
	if !strings.Contains(out, "\x1b[2A") && !strings.Contains(out, "\x1b[2K") {
		t.Fatalf("expected cursor-up or erase-line sequences for multi-line redraw, got %q", out)
	}

	p.mu.Lock()
	gotActive := len(p.active)
	gotDrawn := p.lastDrawnLines
	p.mu.Unlock()
	if gotActive != 2 {
		t.Fatalf("expected 2 active steps, got %d", gotActive)
	}
	if gotDrawn != 2 {
		t.Fatalf("expected lastDrawnLines=2, got %d", gotDrawn)
	}
}

func TestStepCompletionPromotion(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	stepA := p.Start("a", "Stage A")
	stepA.Complete("Did Stage A", []Child{{Icon: CheckMark, Label: "leaf-a", Detail: "[1 thing]"}})
	p.Start("b", "Stage B")
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Did Stage A") {
		t.Fatalf("expected promoted past-tense label, got %q", out)
	}
	if !strings.Contains(out, "leaf-a") {
		t.Fatalf("expected promoted child label, got %q", out)
	}
	if !strings.Contains(out, "Stage B") {
		t.Fatalf("expected new active step after promotion, got %q", out)
	}

	p.mu.Lock()
	active := len(p.active)
	gotDrawn := p.lastDrawnLines
	p.mu.Unlock()
	if active != 1 {
		t.Fatalf("expected 1 active step after promotion, got %d", active)
	}
	if gotDrawn != 1 {
		t.Fatalf("expected lastDrawnLines=1 after promotion, got %d", gotDrawn)
	}
}

func TestConcurrentSteps_NoRace(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s := p.Start("g1", "Goroutine 1")
		for i := 0; i < 50; i++ {
			s.SetProgress(i, 50)
		}
		s.Complete("Goroutine 1 done", nil)
	}()
	go func() {
		defer wg.Done()
		s := p.Start("g2", "Goroutine 2")
		for i := 0; i < 50; i++ {
			s.Advance()
		}
		s.Complete("Goroutine 2 done", nil)
	}()
	wg.Wait()
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Goroutine 1 done") || !strings.Contains(out, "Goroutine 2 done") {
		t.Fatalf("expected both promoted completions, got %q", out)
	}
}

func TestDisabledIsNoop(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, false, "")
	defer p.Stop()

	p.Start("a", "Stage A")
	p.StartStage("b", 10)
	p.AdvanceStage("b", 5, 10)
	p.CompleteStage("b", 10)
	p.CompleteStep("Stage A done", []Child{{Label: "x"}})
	p.Detail("b", "hint")
	p.Stage("hint2")
	p.Advance("c")
	p.Success("done")

	if buf.Len() != 0 {
		t.Fatalf("expected zero writes when disabled, got %q", buf.String())
	}
}

func TestImplicitInitialStep_RendersUntilExplicitStart(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "Resolving things")
	t.Cleanup(p.Stop)

	drainAfter()
	first := buf.String()
	if !strings.Contains(first, "Resolving things") {
		t.Fatalf("expected implicit initial step in render, got %q", first)
	}

	p.Start("real", "Real step")
	drainAfter()

	p.mu.Lock()
	count := len(p.active)
	hasInitial := false
	for _, s := range p.active {
		if s.id == initialStepID {
			hasInitial = true
		}
	}
	p.mu.Unlock()

	if hasInitial {
		t.Fatalf("expected implicit initial step to be dropped after explicit Start")
	}
	if count != 1 {
		t.Fatalf("expected 1 active step after Start (the explicit one), got %d", count)
	}
}

func TestStageDoneLabelLookup_PromotesViaCompleteStep(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	// Engine emits present-progressive label.
	p.StartStage("Detecting dependencies", 4)
	p.AdvanceStage("Detecting dependencies", 4, 4)
	p.CompleteStage("Detecting dependencies", 4)

	// CLI supplies past-tense label + children.
	p.CompleteStep("Detected Dependencies", []Child{{Icon: CheckMark, Label: "Maven", Detail: "[12 packages]"}})
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Detected Dependencies") {
		t.Fatalf("expected past-tense title, got %q", out)
	}
	if !strings.Contains(out, "Maven") {
		t.Fatalf("expected child label, got %q", out)
	}
	if !strings.Contains(out, "[12 packages]") {
		t.Fatalf("expected child detail, got %q", out)
	}
}

func TestCompleteStagePromotesBeforeLaterSummary(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.StartStage("Detecting dependencies", 1)
	p.AdvanceStage("Detecting dependencies", 1, 1)
	p.CompleteStage("Detecting dependencies", 1)
	p.StartStage("Enriching packages", 1)
	drainAfter()

	out := buf.String()
	if !strings.Contains(out, "Detected Dependencies") {
		t.Fatalf("expected completed detection to be promoted independently, got %q", out)
	}
	if !strings.Contains(out, "Enriching packages") {
		t.Fatalf("expected next stage to remain live, got %q", out)
	}

	p.mu.Lock()
	active := len(p.active)
	promoted := len(p.promoted)
	p.mu.Unlock()
	if active != 1 {
		t.Fatalf("expected only next stage to remain active, got %d", active)
	}
	if promoted == 0 {
		t.Fatalf("expected completed stage to be tracked as promoted")
	}
}

func TestCompleteStepIgnoresAlreadyPromotedStage(t *testing.T) {
	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.StartStage("Detecting dependencies", 1)
	p.AdvanceStage("Detecting dependencies", 1, 1)
	p.CompleteStage("Detecting dependencies", 1)
	p.StartStage("Enriching packages", 1)
	drainAfter()

	p.CompleteStep("Detected Dependencies", []Child{{Icon: CheckMark, Label: "Maven", Detail: "[12 packages]"}})
	drainAfter()

	p.mu.Lock()
	active := len(p.active)
	p.mu.Unlock()
	if active != 1 {
		t.Fatalf("late summary should not synthesize a duplicate active step, got %d active steps", active)
	}
	out := buf.String()
	if strings.Contains(out, "Maven") {
		t.Fatalf("late summary for promoted stage should not render duplicate children, got %q", out)
	}
}

func TestMinStepDuration_CompleteBlocksForMinDuration(t *testing.T) {
	t.Setenv(minStepEnvVar, "300")

	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	stepA := p.Start("a", "Stage A")
	// Step.Complete itself must block until the configured window elapses —
	// this is what serializes per-step holds (each step's ✔ is visible
	// for at least minStepDuration before the next CLI operation proceeds).
	start := time.Now()
	stepA.Complete("Did Stage A", nil)
	elapsed := time.Since(start)

	if elapsed < 250*time.Millisecond {
		t.Fatalf("Step.Complete should block ~300ms; took %s", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Step.Complete blocked too long; took %s", elapsed)
	}
}

func TestMinStepDuration_CompleteStepBlocksForSyntheticStep(t *testing.T) {
	t.Setenv(minStepEnvVar, "300")

	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	start := time.Now()
	p.CompleteStep("Detected Dependencies", nil)
	elapsed := time.Since(start)

	if elapsed < 250*time.Millisecond {
		t.Fatalf("CompleteStep should block ~300ms; took %s", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("CompleteStep blocked too long; took %s", elapsed)
	}
}

func TestMinStepDuration_CompleteStageBlocksForMinDuration(t *testing.T) {
	t.Setenv(minStepEnvVar, "300")

	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	p.StartStage("Detecting dependencies", 1)
	p.AdvanceStage("Detecting dependencies", 1, 1)

	start := time.Now()
	p.CompleteStage("Detecting dependencies", 1)
	elapsed := time.Since(start)

	if elapsed < 250*time.Millisecond {
		t.Fatalf("CompleteStage should block ~300ms; took %s", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("CompleteStage blocked too long; took %s", elapsed)
	}
}

func TestMinStepDuration_TwoStepsAreSequential(t *testing.T) {
	t.Setenv(minStepEnvVar, "200")

	var buf safeBuffer
	p := New(&buf, true, "")
	t.Cleanup(p.Stop)

	start := time.Now()
	a := p.Start("a", "Stage A")
	a.Complete("Did Stage A", nil) // blocks ~200ms
	b := p.Start("b", "Stage B")
	b.Complete("Did Stage B", nil) // blocks ~200ms
	elapsed := time.Since(start)

	// Two sequential 200ms holds should give ~400ms total — proving the
	// holds are per-step, not bulk-applied at exit.
	if elapsed < 350*time.Millisecond {
		t.Fatalf("two sequential completes should take ~400ms; took %s", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("two sequential completes blocked too long; took %s", elapsed)
	}
}

func TestMinStepDuration_StopBypassesHold(t *testing.T) {
	t.Setenv(minStepEnvVar, "5000") // 5s: would block forever in a normal flow

	var buf safeBuffer
	p := New(&buf, true, "")

	// Open a step but do NOT call Complete (which would itself block for
	// the 5s hold). Stop is the --interactive handoff path: it must drop
	// any pending steps and return instantly, regardless of the hold.
	_ = p.Start("a", "Stage A")

	start := time.Now()
	p.Stop()
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("Stop should not wait for min-duration hold; took %s", elapsed)
	}

	p.mu.Lock()
	active := len(p.active)
	p.mu.Unlock()
	if active != 0 {
		t.Fatalf("expected zero active steps after Stop, got %d", active)
	}
}

func TestMinStepDuration_SuccessHonorsHold(t *testing.T) {
	t.Setenv(minStepEnvVar, "300")

	var buf safeBuffer
	p := New(&buf, true, "")

	stepA := p.Start("a", "Stage A")
	stepA.Complete("Did Stage A", nil)

	// Success is the normal exit path; with the hidden knob set, it must
	// wait for the held step to satisfy its minimum on-screen duration
	// before finalizing and returning control to the caller. Without this,
	// fast scans would force-promote everything in microseconds and the
	// knob would be useless.
	start := time.Now()
	p.Success("Resolved Graph")
	elapsed := time.Since(start)

	if elapsed < 250*time.Millisecond {
		t.Fatalf("Success should wait for min-duration hold; only took %s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Success waited too long; took %s (expected ~300ms)", elapsed)
	}
}

func TestReadMinStepDuration_RejectsInvalid(t *testing.T) {
	cases := []string{"", "0", "-1", "abc", "  "}
	for _, value := range cases {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv(minStepEnvVar, value)
			if got := readMinStepDuration(); got != 0 {
				t.Fatalf("expected zero duration for %q, got %s", value, got)
			}
		})
	}
}

func TestReadMinStepDuration_ParsesMilliseconds(t *testing.T) {
	t.Setenv(minStepEnvVar, "250")
	if got := readMinStepDuration(); got != 250*time.Millisecond {
		t.Fatalf("expected 250ms, got %s", got)
	}
}

// safeBuffer is a bytes.Buffer guarded by a mutex so the ticker goroutine and
// the test goroutine don't race on Write/String.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *safeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}
