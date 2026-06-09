// Package progress renders a CLI progress display: a live region of per-step
// lines, each animating its own spinner and bubbles-rendered progress bar,
// plus a stream of completed steps that get promoted in place (rewritten as
// a past-tense title with their child tree) and scroll into history as new
// steps start.
//
// Progress satisfies the engine.ProgressReporter interface (StartStage /
// AdvanceStage / CompleteStage) so the pipeline can drive coarse progress
// events, while command code can also open finer-grained step handles via
// Start / StartWithDoneLabel.
package progress

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	bprogress "github.com/charmbracelet/bubbles/progress"
	bspinner "github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)

// Visual marks rendered before completed-step / child labels.
const (
	CheckMark   = "✔"
	CrossMark   = "✘"
	WarningMark = "⚠"

	titleWidth      = 35
	childLabelWidth = 25
	barWidth        = 20

	hideCursorSeq = "\x1b[?25l"
	showCursorSeq = "\x1b[?25h"
	eraseLineSeq  = "\x1b[2K"

	initialStepID = "__initial__"

	// minStepEnvVar is a hidden, dev-only knob. When set to a positive integer
	// it is interpreted as milliseconds: every step is held in the live region
	// as a ✔ line for at least that long before being promoted to the frozen
	// (scrolled-away) block. Lets you actually see steps that complete in a
	// few milliseconds (registry init, container reference resolution, etc.).
	// Example: BOMLY_PROGRESS_MIN_STEP_MS=600 ./bin/bomly scan
	minStepEnvVar = "BOMLY_PROGRESS_MIN_STEP_MS"
)

// spin is the curated frame set we render. We deliberately don't run
// bubbles/spinner's tea.Model — we just borrow its frame slice + FPS so we
// stay aligned with the rest of the Charm aesthetic.
var spin = bspinner.MiniDot

// stageDoneLabels maps an engine stage's active (present-progressive) label to
// the past-tense label the CLI later supplies via CompleteStep. Populated
// implicitly at Start time so that CompleteStep("Detected Dependencies", …)
// finds the same step opened by StartStage("Detecting dependencies", …).
var stageDoneLabels = map[string]string{
	"Detecting dependencies": "Detected Dependencies",
	"Enriching packages":     "Enriched packages",
	"Analyzing reachability": "Analyzed reachability",
	"Evaluating policy":      "Evaluated policy",
}

var (
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))  // magenta
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // green
	failStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))   // red
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))  // yellow
	stageStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
	titleStyle   = lipgloss.NewStyle().Bold(true)
	detailStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
	treeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
)

// Child describes one sub-item rendered beneath a completed task.
type Child struct {
	Icon   string // e.g. CheckMark, CrossMark, WarningMark, or "" for a plain item
	Label  string // e.g. "Maven Detector", "subproject-a"
	Detail string // e.g. "[59 packages]"
}

type stepState uint8

const (
	stepActive    stepState = iota // spinner animating, bar live
	stepFinishing                  // engine signaled CompleteStage; ✔ icon, bar at 100%, awaiting children
	stepSucceeded                  // ready to promote with ✔ + children
	stepFailed                     // ready to promote with ✘
)

// Step is the handle for one line in the live region. It is returned by
// Start / StartWithDoneLabel and used by callers that want to drive a
// dedicated progress line directly (rather than via the label-keyed shim).
type Step struct {
	p         *Progress
	id        string
	active    string
	done      string
	bar       bprogress.Model
	completed int
	total     int
	detail    string
	state     stepState
	children  []Child
	startedAt time.Time // wall-clock time the step entered the live region
	doneAt    time.Time // wall-clock time the step transitioned to stepSucceeded / stepFailed
}

// SetTotal sets the denominator for this step's progress bar.
func (s *Step) SetTotal(n int) {
	if s == nil || s.p == nil {
		return
	}
	s.p.mu.Lock()
	if n < 0 {
		n = 0
	}
	s.total = n
	if s.completed > n {
		s.completed = n
	}
	s.p.mu.Unlock()
}

// Advance increments completed by one.
func (s *Step) Advance() {
	if s == nil || s.p == nil {
		return
	}
	s.p.mu.Lock()
	s.completed++
	if s.total > 0 && s.completed > s.total {
		s.completed = s.total
	}
	s.p.mu.Unlock()
}

// SetProgress replaces completed/total atomically.
func (s *Step) SetProgress(completed, total int) {
	if s == nil || s.p == nil {
		return
	}
	if total < 0 {
		total = 0
	}
	if completed < 0 {
		completed = 0
	}
	if total > 0 && completed > total {
		completed = total
	}
	s.p.mu.Lock()
	s.completed = completed
	s.total = total
	s.p.mu.Unlock()
}

// SetDetail updates the hint text shown to the right of the bar on this step.
func (s *Step) SetDetail(text string) {
	if s == nil || s.p == nil {
		return
	}
	s.p.mu.Lock()
	s.detail = strings.TrimSpace(text)
	s.p.mu.Unlock()
}

// Complete marks the step as succeeded with the supplied past-tense label and
// child tree. The renderer holds the line for p.minStepDuration after this
// call (via the doneAt stamp) and the call itself blocks for the same hold,
// so each step has its own visible ✔ window before the next operation
// proceeds.
func (s *Step) Complete(doneLabel string, children []Child) {
	if s == nil || s.p == nil {
		return
	}
	s.p.mu.Lock()
	if doneLabel != "" {
		s.done = doneLabel
	}
	if s.done == "" {
		s.done = s.active
	}
	if s.total > 0 {
		s.completed = s.total
	}
	s.children = children
	s.state = stepSucceeded
	s.doneAt = time.Now()
	doneAt := s.doneAt
	s.p.mu.Unlock()
	s.p.holdAfterDone(doneAt)
}

// Fail marks the step as failed with the supplied past-tense label.
// Blocks for p.minStepDuration after the state transition (same hold
// semantics as Complete) so failures stay readable.
func (s *Step) Fail(doneLabel string) {
	if s == nil || s.p == nil {
		return
	}
	s.p.mu.Lock()
	if doneLabel != "" {
		s.done = doneLabel
	}
	if s.done == "" {
		s.done = s.active
	}
	s.state = stepFailed
	s.doneAt = time.Now()
	doneAt := s.doneAt
	s.p.mu.Unlock()
	s.p.holdAfterDone(doneAt)
}

type completedTask struct {
	label    string
	failed   bool
	children []Child
}

// Progress renders the live region. Safe for concurrent use.
type Progress struct {
	writer  io.Writer
	enabled bool

	mu              sync.Mutex
	active          []*Step
	pastToID        map[string]string
	frame           int
	lastDrawnLines  int
	cursorHidden    bool
	minStepDuration time.Duration // minimum time each step is held in the live region; see minStepEnvVar

	stopCh    chan struct{}
	doneCh    chan struct{}
	finished  bool
	separated bool
}

// holdAfterDone blocks the caller until at least p.minStepDuration has
// elapsed since doneAt. Caller must hold no locks. No-op when the hidden
// knob is unset / doneAt is zero / the hold has already elapsed.
//
// Used by every "this step is now done" entry point (Step.Complete /
// Step.Fail / Progress.CompleteStep / Progress.Advance / Progress.Success
// / Progress.Fail) so each step gets its own visible ✔ window before the
// next operation can proceed. This is what makes the hold per-step rather
// than one bulk wait at exit.
func (p *Progress) holdAfterDone(doneAt time.Time) {
	if p == nil || p.minStepDuration <= 0 || doneAt.IsZero() {
		return
	}
	elapsed := time.Since(doneAt)
	if elapsed >= p.minStepDuration {
		return
	}
	time.Sleep(p.minStepDuration - elapsed)
}

// readMinStepDuration parses the minStepEnvVar env var as a positive integer
// number of milliseconds. Returns zero (the feature disabled) on any of:
// unset, empty, non-numeric, zero, or negative. Hidden / dev-only knob.
func readMinStepDuration() time.Duration {
	raw := strings.TrimSpace(os.Getenv(minStepEnvVar))
	if raw == "" {
		return 0
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// New creates a Progress instance. When enabled is false, all methods are
// no-ops. A non-empty initial label opens an implicit step that disappears
// silently once any explicit Start / StartStage is called.
func New(writer io.Writer, enabled bool, label string) *Progress {
	p := &Progress{
		writer:          writer,
		enabled:         enabled,
		pastToID:        make(map[string]string),
		minStepDuration: readMinStepDuration(),
	}
	if !p.enabled {
		return p
	}
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	if label != "" {
		p.active = append(p.active, &Step{
			p:         p,
			id:        initialStepID,
			active:    label,
			bar:       newBar(),
			state:     stepActive,
			startedAt: time.Now(),
		})
	}
	go p.run()
	return p
}

func newBar() bprogress.Model {
	m := bprogress.New(bprogress.WithDefaultGradient(), bprogress.WithoutPercentage())
	m.Width = barWidth
	return m
}

func (p *Progress) run() {
	defer close(p.doneCh)
	ticker := time.NewTicker(spin.FPS)
	defer ticker.Stop()

	p.draw()
	for {
		select {
		case <-ticker.C:
			p.tickFrame()
			p.draw()
		case <-p.stopCh:
			return
		}
	}
}

func (p *Progress) tickFrame() {
	p.mu.Lock()
	p.frame = (p.frame + 1) % len(spin.Frames)
	p.mu.Unlock()
}

// Start opens a new step in the live region.
func (p *Progress) Start(id, activeLabel string) *Step {
	return p.StartWithDoneLabel(id, activeLabel, "")
}

// StartWithDoneLabel opens a new step and pre-registers its past-tense label
// so subsequent CompleteStep(doneLabel, …) finds the same step.
func (p *Progress) StartWithDoneLabel(id, activeLabel, doneLabel string) *Step {
	if p == nil || !p.enabled {
		return &Step{} // detached no-op handle
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.finished {
		return &Step{}
	}
	p.dropImplicitInitialLocked()

	// If a step with this id already exists, return it (idempotent reopen).
	for _, s := range p.active {
		if s.id == id {
			return s
		}
	}
	s := &Step{
		p:         p,
		id:        id,
		active:    activeLabel,
		bar:       newBar(),
		state:     stepActive,
		startedAt: time.Now(),
	}
	p.active = append(p.active, s)
	if activeLabel != "" {
		p.pastToID[activeLabel] = id
	}
	if doneLabel != "" {
		p.pastToID[doneLabel] = id
	}
	return s
}

// dropImplicitInitialLocked removes the placeholder step opened by New() with
// an initial label, the first time an explicit step is started. Must be
// called with p.mu held.
func (p *Progress) dropImplicitInitialLocked() {
	if len(p.active) == 0 {
		return
	}
	if p.active[0].id == initialStepID {
		p.active = p.active[1:]
	}
}

// CompleteStep finalises the step matching doneLabel (or the most-recent
// stepActive / stepFinishing step) with the supplied children. Blocks for
// p.minStepDuration after the state transition (see holdAfterDone) so each
// step has its own visible ✔ window before the next CLI operation proceeds.
func (p *Progress) CompleteStep(doneLabel string, children []Child) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	s := p.findStepLocked(doneLabel)
	now := time.Now()
	if s == nil {
		// No matching step: emit a synthetic step that the renderer will
		// promote on its next draw. This preserves today's "buffered pending
		// step" behavior when callers complete a label they never opened.
		p.dropImplicitInitialLocked()
		s = &Step{
			p:         p,
			id:        doneLabel,
			active:    doneLabel,
			bar:       newBar(),
			state:     stepSucceeded,
			startedAt: now,
		}
		p.active = append(p.active, s)
	}
	s.state = stepSucceeded
	s.done = doneLabel
	s.children = children
	if s.total > 0 {
		s.completed = s.total
	}
	s.doneAt = now
	doneAt := s.doneAt
	p.mu.Unlock()
	p.holdAfterDone(doneAt)
}

// Advance flushes any prior implicit/in-flight steps and starts a new
// labeled step. Preserves the legacy single-spinner API for callers like
// scan_cmd's "Writing SBOM output" transition. Each silently-promoted prior
// step gets its own hold (sequential, so the user sees each one transition).
func (p *Progress) Advance(label string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	now := time.Now()
	// Promote any prior stepActive/stepFinishing steps as silent successes so
	// they don't perpetually spin once the caller has moved on.
	var holds []time.Time
	for _, s := range p.active {
		if s.state == stepActive || s.state == stepFinishing {
			if s.id == initialStepID {
				continue // implicit step is dropped, not promoted
			}
			s.state = stepSucceeded
			if s.done == "" {
				s.done = s.active
			}
			s.doneAt = now
			holds = append(holds, s.doneAt)
		}
	}
	p.dropImplicitInitialLocked()
	s := &Step{
		p:         p,
		id:        label,
		active:    label,
		bar:       newBar(),
		state:     stepActive,
		startedAt: now,
	}
	p.active = append(p.active, s)
	if label != "" {
		p.pastToID[label] = label
	}
	p.mu.Unlock()
	// Sleep so each silently-promoted prior step gets a visible ✔ window.
	// They all share the same doneAt (now) so a single sleep covers them.
	if len(holds) > 0 {
		p.holdAfterDone(holds[0])
	}
}

// findStepLocked returns the step whose pastToID maps to doneLabel, falling
// back to the most-recent active/finishing step, then the most-recent step
// of any state. Returns nil if active is empty. Must be called with p.mu
// held.
func (p *Progress) findStepLocked(doneLabel string) *Step {
	if id, ok := p.pastToID[doneLabel]; ok {
		for _, s := range p.active {
			if s.id == id {
				return s
			}
		}
	}
	for i := len(p.active) - 1; i >= 0; i-- {
		s := p.active[i]
		if s.state == stepActive || s.state == stepFinishing {
			return s
		}
	}
	return nil
}

// findStepByActiveLabelLocked returns the most-recent step whose active label
// matches. Must be called with p.mu held.
func (p *Progress) findStepByActiveLabelLocked(label string) *Step {
	if id, ok := p.pastToID[label]; ok {
		for _, s := range p.active {
			if s.id == id {
				return s
			}
		}
	}
	for i := len(p.active) - 1; i >= 0; i-- {
		if p.active[i].active == label {
			return p.active[i]
		}
	}
	return nil
}

// Stage updates the hint on the most-recent active step. Kept for
// backwards-compatibility with the legacy single-spinner API.
func (p *Progress) Stage(text string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.active) - 1; i >= 0; i-- {
		if p.active[i].state == stepActive || p.active[i].state == stepFinishing {
			p.active[i].detail = strings.TrimSpace(text)
			return
		}
	}
}

// Detail updates the hint on the step keyed by activeLabel. Implements the
// engine's DetailProgressReporter interface.
func (p *Progress) Detail(label, detail string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.findStepByActiveLabelLocked(label)
	if s == nil {
		// As a fallback, open a step so the caller sees a line even when no
		// explicit Start preceded the Detail call. This matches the legacy
		// behavior where Detail also updated the spinner's label.
		p.dropImplicitInitialLocked()
		s = &Step{
			p:         p,
			id:        label,
			active:    label,
			bar:       newBar(),
			state:     stepActive,
			startedAt: time.Now(),
		}
		p.active = append(p.active, s)
		if label != "" {
			p.pastToID[label] = label
		}
	}
	s.detail = strings.TrimSpace(detail)
}

// StartStage / AdvanceStage / CompleteStage satisfy engine.ProgressReporter.
// They route engine-emitted stage events through the label-keyed shim so the
// CLI can later supply a past-tense label + children via CompleteStep.
func (p *Progress) StartStage(label string, total int) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.dropImplicitInitialLocked()
	s := p.findStepByActiveLabelLocked(label)
	if s == nil {
		s = &Step{
			p:         p,
			id:        label,
			active:    label,
			bar:       newBar(),
			state:     stepActive,
			startedAt: time.Now(),
		}
		p.active = append(p.active, s)
		if label != "" {
			p.pastToID[label] = label
		}
	}
	if done, ok := stageDoneLabels[label]; ok {
		p.pastToID[done] = s.id
	}
	if total < 0 {
		total = 0
	}
	s.total = total
	s.completed = 0
	p.mu.Unlock()
}

func (p *Progress) AdvanceStage(label string, completed, total int) {
	if p == nil || !p.enabled {
		return
	}
	if total < 0 {
		total = 0
	}
	if completed < 0 {
		completed = 0
	}
	if total > 0 && completed > total {
		completed = total
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	s := p.findStepByActiveLabelLocked(label)
	if s == nil {
		// Auto-open if the caller advances before starting.
		p.dropImplicitInitialLocked()
		s = &Step{
			p:         p,
			id:        label,
			active:    label,
			bar:       newBar(),
			state:     stepActive,
			startedAt: time.Now(),
		}
		p.active = append(p.active, s)
		if label != "" {
			p.pastToID[label] = label
		}
		if done, ok := stageDoneLabels[label]; ok {
			p.pastToID[done] = s.id
		}
	}
	s.total = total
	s.completed = completed
}

func (p *Progress) CompleteStage(label string, total int) {
	if p == nil || !p.enabled {
		return
	}
	if total < 0 {
		total = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	s := p.findStepByActiveLabelLocked(label)
	if s == nil {
		return
	}
	s.total = total
	s.completed = total
	// Engine signaled completion but the CLI still needs to supply the
	// past-tense label + children. Hold the step in the region with a ✔
	// icon and a full bar until CompleteStep arrives.
	if s.state == stepActive {
		s.state = stepFinishing
	}
}

// Success promotes the most-recent active step (or the step matching label
// via pastToID) and stops the renderer. Subsequent calls are no-ops.
func (p *Progress) Success(label string) {
	p.finishAll(label, stepSucceeded, nil)
}

// SuccessWithChildren promotes the most-recent active step with children
// and stops the renderer.
func (p *Progress) SuccessWithChildren(label string, children []Child) {
	p.finishAll(label, stepSucceeded, children)
}

// Fail promotes the most-recent active step with a ✘ icon and stops the
// renderer.
func (p *Progress) Fail(label string) {
	p.finishAll(label, stepFailed, nil)
}

// Stop halts the renderer without writing a final line. Cursor visibility
// is restored. Subsequent calls are no-ops.
func (p *Progress) Stop() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	// Drop any still-active steps so they don't render in the final cleanup.
	p.active = nil
	p.mu.Unlock()

	close(p.stopCh)
	<-p.doneCh
	p.finalDraw()
}

func (p *Progress) finishAll(doneLabel string, state stepState, children []Child) {
	if !p.enabled {
		// Cobra defer-Fail paths land here when progress is disabled (e.g.
		// non-TTY). Nothing to render.
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}

	now := time.Now()
	target := p.findStepLocked(doneLabel)
	if target == nil {
		// No step matches — synthesize one so the user sees a final block.
		p.dropImplicitInitialLocked()
		target = &Step{
			p:         p,
			id:        doneLabel,
			active:    doneLabel,
			bar:       newBar(),
			state:     stepActive,
			startedAt: now,
		}
		p.active = append(p.active, target)
	}
	target.state = state
	target.done = doneLabel
	if state != stepFailed {
		target.children = children
	}
	target.doneAt = now

	// Promote any other still-running steps as silent successes so the live
	// region drains completely. They share the same doneAt so a single hold
	// covers all of them.
	for _, s := range p.active {
		if s == target {
			continue
		}
		if s.state == stepActive || s.state == stepFinishing {
			s.state = stepSucceeded
			if s.done == "" {
				s.done = s.active
			}
			s.doneAt = now
		}
	}

	p.finished = true
	p.mu.Unlock()

	// Honor the hold on the target step (and any siblings sharing doneAt)
	// so the user sees the final ✔ before the program exits.
	p.holdAfterDone(now)

	close(p.stopCh)
	<-p.doneCh
	p.finalDraw()
}

// finalDraw flushes any pending promotions, restores the cursor, and clears
// the live region. Safe to call only after the run goroutine has exited.
//
// Each call site that transitions a step to done (Step.Complete, Step.Fail,
// CompleteStep, Advance, finishAll) has already blocked for its own
// minStepDuration window via holdAfterDone, so by the time we get here
// there is nothing left to wait on — we just force-promote and write.
func (p *Progress) finalDraw() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.active {
		if s.state == stepSucceeded || s.state == stepFailed {
			s.doneAt = time.Time{}
		}
	}
	p.drawLocked()
	if p.cursorHidden {
		_, _ = p.writer.Write([]byte(showCursorSeq))
		p.cursorHidden = false
	}
}

// SeparateReport writes a blank line between the progress output and any
// human-readable report that follows on stdout.
func (p *Progress) SeparateReport() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	if !p.finished || p.separated {
		p.mu.Unlock()
		return
	}
	p.separated = true
	p.mu.Unlock()

	_, _ = fmt.Fprintln(p.writer)
}

func (p *Progress) draw() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drawLocked()
}

// drawLocked promotes any completed steps to frozen blocks and redraws the
// remaining live region. Must be called with p.mu held.
func (p *Progress) drawLocked() {
	promotions := p.collectPromotionsLocked()
	frame := spin.Frames[p.frame]
	prev := p.lastDrawnLines

	var buf bytes.Buffer
	if !p.cursorHidden {
		buf.WriteString(hideCursorSeq)
		p.cursorHidden = true
	}

	// Move to top of previous live region and erase it.
	if prev > 0 {
		fmt.Fprintf(&buf, "\x1b[%dA", prev)
	}
	buf.WriteString("\r")
	for i := 0; i < prev; i++ {
		buf.WriteString(eraseLineSeq)
		if i < prev-1 {
			buf.WriteString("\n")
		}
	}
	if prev > 1 {
		fmt.Fprintf(&buf, "\x1b[%dA", prev-1)
	}
	if prev > 0 {
		buf.WriteString("\r")
	}

	// Write promoted (now permanent) blocks above the new live region.
	for _, promo := range promotions {
		buf.WriteString(renderFrozenBlock(promo))
	}

	// Write the new live region.
	newLines := 0
	for _, s := range p.active {
		buf.WriteString(renderActiveLine(s, frame))
		buf.WriteString("\n")
		newLines++
	}
	p.lastDrawnLines = newLines

	if buf.Len() == 0 {
		return
	}
	_, _ = p.writer.Write(buf.Bytes())
}

func (p *Progress) collectPromotionsLocked() []*Step {
	if len(p.active) == 0 {
		return nil
	}
	now := time.Now()
	var promos []*Step
	kept := p.active[:0]
	for _, s := range p.active {
		if s.state == stepSucceeded || s.state == stepFailed {
			// Hidden dev/test knob: hold the step in the live region with
			// its terminal ✔/✘ icon for at least minStepDuration after it
			// transitioned to done. The Complete/Fail/CompleteStep call site
			// also blocks for the same duration (see holdAfterDone), so the
			// renderer would normally not promote until the call returns —
			// but the ticker can still fire during that sleep, hence this
			// guard.
			if p.minStepDuration > 0 && !s.doneAt.IsZero() && now.Sub(s.doneAt) < p.minStepDuration {
				kept = append(kept, s)
				continue
			}
			promos = append(promos, s)
			continue
		}
		kept = append(kept, s)
	}
	p.active = kept
	return promos
}

func renderActiveLine(s *Step, frame string) string {
	var icon string
	switch s.state {
	case stepSucceeded, stepFinishing:
		icon = successStyle.Render(CheckMark)
	case stepFailed:
		icon = failStyle.Render(CrossMark)
	default:
		icon = spinnerStyle.Render(frame)
	}
	// Use the past-tense label when one is set (true for steps held back by
	// minStepDuration) so the held line reads the same as the eventual
	// frozen block.
	headerLabel := s.active
	if (s.state == stepSucceeded || s.state == stepFailed) && s.done != "" {
		headerLabel = s.done
	}
	title := titleStyle.Width(titleWidth).Render(headerLabel)

	percent := 0.0
	if s.total > 0 {
		percent = float64(s.completed) / float64(s.total)
	}
	if s.state == stepFinishing || s.state == stepSucceeded {
		percent = 1.0
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	bar := s.bar.ViewAs(percent)
	pct := fmt.Sprintf(" %3d%%", int(percent*100+0.5))

	line := fmt.Sprintf(" %s %s %s%s", icon, title, bar, pct)
	if s.detail != "" {
		line += " " + stageStyle.Render(s.detail)
	}
	return line
}

func renderFrozenBlock(s *Step) string {
	icon := successStyle.Render(CheckMark)
	if s.state == stepFailed {
		icon = failStyle.Render(CrossMark)
	}
	label := s.done
	if label == "" {
		label = s.active
	}
	head := fmt.Sprintf(" %s %s\n", icon, titleStyle.Render(label))
	if len(s.children) == 0 {
		return head
	}
	t := tree.New().EnumeratorStyle(treeStyle)
	for _, c := range s.children {
		t = t.Child(renderChildNode(c))
	}
	body := strings.TrimRight(t.String(), "\n")

	var buf bytes.Buffer
	buf.WriteString(head)
	for _, line := range strings.Split(body, "\n") {
		buf.WriteString("   ")
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	return buf.String()
}

func renderChildNode(c Child) string {
	var icon string
	if c.Icon != "" {
		switch c.Icon {
		case WarningMark:
			icon = warnStyle.Render(c.Icon) + " "
		case CrossMark:
			icon = failStyle.Render(c.Icon) + " "
		case CheckMark:
			icon = successStyle.Render(c.Icon) + " "
		default:
			icon = c.Icon + " "
		}
	}
	label := lipgloss.NewStyle().Width(childLabelWidth).Render(c.Label)
	if c.Detail != "" {
		return icon + label + " " + detailStyle.Render(c.Detail)
	}
	return icon + label
}

// completedTask is preserved for source-level compatibility with prior tests
// that constructed Progress as a struct literal. It is unused by the new
// renderer but stays so external snapshots compile.
var _ = completedTask{}
