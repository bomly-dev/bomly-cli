// Package progress renders a CLI progress display: a single live-updating spinner line
// for the current step plus a buffered list of completed steps that flushes to the writer
// when the next step starts. Each completed step can carry a tree of Child rows describing
// what happened (e.g. detector results, finding counts).
//
// Progress satisfies the scan.ProgressReporter interface (StartStage / AdvanceStage /
// CompleteStage), so it can drive the pipeline's coarse progress events while also being
// used directly by command code for finer-grained step reporting.
package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// spinnerFrames mirrors the braille-dot spinner used by syft / bubbly.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Visual marks rendered before completed-step / child labels.
const (
	CheckMark   = "✔"
	CrossMark   = "✘"
	WarningMark = "⚠"

	titleWidth      = 35
	childLabelWidth = 25
	barWidth        = 20
	spinnerFPS      = 100 * time.Millisecond
)

var (
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))  // magenta
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // green
	failStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))   // red
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))  // yellow
	stageStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
	titleStyle   = lipgloss.NewStyle().Bold(true)
	detailStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
)

// Child describes one sub-item rendered beneath a completed task.
type Child struct {
	Icon   string // e.g. CheckMark, CrossMark, WarningMark, or "" for a plain item
	Label  string // e.g. "Maven Detector", "subproject-a"
	Detail string // e.g. "[59 packages]"
}

type completedTask struct {
	label    string
	failed   bool
	children []Child
}

// Progress renders a single live spinner line plus a flushed list of completed steps.
// It is safe for concurrent use.
type Progress struct {
	writer       io.Writer
	enabled      bool
	label        string
	stage        string
	pendingSteps []completedTask
	mu           sync.Mutex
	stopCh       chan struct{}
	doneCh       chan struct{}
	finished     bool
	separated    bool
}

// New creates a Progress instance. When enabled is false, all methods are no-ops —
// useful when the host stream cannot render ANSI escapes (piped, not a TTY, etc.).
func New(writer io.Writer, enabled bool, label string) *Progress {
	p := &Progress{
		writer:  writer,
		enabled: enabled,
		label:   label,
	}
	if !p.enabled {
		return p
	}
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	go p.run()
	return p
}

func (p *Progress) run() {
	defer close(p.doneCh)
	ticker := time.NewTicker(spinnerFPS)
	defer ticker.Stop()

	frame := 0
	p.renderActive(spinnerFrames[frame])
	for {
		select {
		case <-ticker.C:
			frame = (frame + 1) % len(spinnerFrames)
			p.renderActive(spinnerFrames[frame])
		case <-p.stopCh:
			return
		}
	}
}

// CompleteStep buffers a completed task with optional children. It will be
// printed on the next call to Advance, Success, or Fail.
func (p *Progress) CompleteStep(label string, children []Child) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.pendingSteps = append(p.pendingSteps, completedTask{label: label, children: children})
	p.mu.Unlock()
}

// Advance flushes all pending completed steps, then starts a new spinner task.
func (p *Progress) Advance(label string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	steps := p.pendingSteps
	p.pendingSteps = nil
	if len(steps) == 0 {
		steps = []completedTask{{label: p.label}}
	}
	p.label = label
	p.stage = ""
	p.mu.Unlock()

	p.flushSteps(steps)
	p.renderActive(spinnerFrames[0])
}

// Stage updates the hint text shown alongside the current spinner.
func (p *Progress) Stage(text string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.stage = text
	p.mu.Unlock()
}

// StartStage / AdvanceStage / CompleteStage satisfy scan.ProgressReporter.
func (p *Progress) StartStage(label string, total int) {
	p.setStageProgress(label, 0, total)
}

func (p *Progress) AdvanceStage(label string, completed, total int) {
	p.setStageProgress(label, completed, total)
}

func (p *Progress) CompleteStage(label string, total int) {
	p.setStageProgress(label, total, total)
}

func (p *Progress) setStageProgress(label string, completed, total int) {
	if !p.enabled {
		return
	}
	if total < 1 {
		total = 1
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	percent := completed * 100 / total
	p.mu.Lock()
	p.label = label
	p.stage = fmt.Sprintf("%s %3d%%", formatProgressBar(completed, total), percent)
	p.mu.Unlock()
	p.renderActive(spinnerFrames[0])
}

// Success prints the final task with a check mark and stops the spinner.
func (p *Progress) Success(label string) {
	p.finish(completedTask{label: label}, false)
}

// SuccessWithChildren prints the final task with children and stops the spinner.
func (p *Progress) SuccessWithChildren(label string, children []Child) {
	p.finish(completedTask{label: label, children: children}, false)
}

// Fail prints the final task with a cross mark and stops the spinner.
func (p *Progress) Fail(label string) {
	p.finish(completedTask{label: label, failed: true}, true)
}

// Stop halts the spinner without writing a final line.
func (p *Progress) Stop() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	p.pendingSteps = nil
	p.mu.Unlock()

	close(p.stopCh)
	<-p.doneCh
	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K")
}

func (p *Progress) finish(final completedTask, failed bool) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	steps := p.pendingSteps
	p.pendingSteps = nil
	p.mu.Unlock()

	close(p.stopCh)
	<-p.doneCh

	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K")
	for _, t := range steps {
		p.writeTaskBlock(t)
	}
	p.writeTaskBlock(final)
}

// SeparateReport writes a small visual divider after progress completes and
// before a human-readable report is emitted on stdout.
func (p *Progress) SeparateReport() {
	if !p.enabled {
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

func (p *Progress) flushSteps(steps []completedTask) {
	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K")
	for _, t := range steps {
		p.writeTaskBlock(t)
	}
}

func (p *Progress) writeTaskBlock(t completedTask) {
	_, _ = fmt.Fprintln(p.writer, formatCompletedLine(t))
	for i, child := range t.children {
		isLast := i == len(t.children)-1
		_, _ = fmt.Fprintln(p.writer, formatChildLine(child, isLast))
	}
}

func (p *Progress) renderActive(frame string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	label := p.label
	stage := p.stage
	p.mu.Unlock()

	line := formatSpinnerLine(frame, label, stage)
	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K"+line)
}

func formatSpinnerLine(frame, label, stage string) string {
	icon := spinnerStyle.Render(frame)
	title := titleStyle.Width(titleWidth).Render(label)
	if stage != "" {
		return fmt.Sprintf(" %s %s %s", icon, title, stageStyle.Render(stage))
	}
	return fmt.Sprintf(" %s %s", icon, title)
}

func formatProgressBar(completed, total int) string {
	if total < 1 {
		total = 1
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	filled := completed * barWidth / total
	if completed > 0 && filled == 0 {
		filled = 1
	}
	if completed < total && filled == barWidth {
		filled = barWidth - 1
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat(".", barWidth-filled) + "]"
}

func formatCompletedLine(t completedTask) string {
	var icon string
	if t.failed {
		icon = failStyle.Render(CrossMark)
	} else {
		icon = successStyle.Render(CheckMark)
	}
	title := titleStyle.Render(t.label)
	return fmt.Sprintf(" %s %s", icon, title)
}

func formatChildLine(child Child, last bool) string {
	connector := "├──"
	if last {
		connector = "└──"
	}
	if child.Icon != "" {
		var icon string
		switch child.Icon {
		case WarningMark:
			icon = warnStyle.Render(child.Icon)
		case CrossMark:
			icon = failStyle.Render(child.Icon)
		default:
			icon = successStyle.Render(child.Icon)
		}
		label := lipgloss.NewStyle().Width(childLabelWidth).Render(child.Label)
		if child.Detail != "" {
			return fmt.Sprintf("   %s %s %s %s", stageStyle.Render(connector), icon, label, detailStyle.Render(child.Detail))
		}
		return fmt.Sprintf("   %s %s %s", stageStyle.Render(connector), icon, label)
	}
	label := child.Label
	if child.Detail != "" {
		label += " " + detailStyle.Render(child.Detail)
	}
	return fmt.Sprintf("   %s %s", stageStyle.Render(connector), label)
}
