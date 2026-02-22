package cli

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// spinnerFrames mirrors the braille-dot spinner used by syft / bubbly.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	progressCheckMark       = "✔"
	progressCrossMark       = "✘"
	progressWarningMark     = "⚠"
	progressTitleWidth      = 35
	progressChildLabelWidth = 25
	progressSpinnerFPS      = 100 * time.Millisecond
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

// progressChild describes one sub-item rendered beneath a completed task.
type progressChild struct {
	Icon   string // e.g. "✔", "✘", or "" for plain items
	Label  string // e.g. "Maven Detector", "subproject-a"
	Detail string // e.g. "[59 packages]"
}

type completedTask struct {
	label    string
	failed   bool
	children []progressChild
}

type commandProgress struct {
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

func newCommandProgress(streams commandStreams, label string) *commandProgress {
	p := &commandProgress{
		writer:  streams.notificationWriter(),
		enabled: streams.canRenderProgress(),
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

func (p *commandProgress) run() {
	defer close(p.doneCh)
	ticker := time.NewTicker(progressSpinnerFPS)
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
func (p *commandProgress) CompleteStep(label string, children []progressChild) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.pendingSteps = append(p.pendingSteps, completedTask{label: label, children: children})
	p.mu.Unlock()
}

// Advance flushes all pending completed steps, then starts a new spinner task.
func (p *commandProgress) Advance(label string) {
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
func (p *commandProgress) Stage(text string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.stage = text
	p.mu.Unlock()
}

// Success prints the final task with a check mark and stops the spinner.
func (p *commandProgress) Success(label string) {
	p.finish(completedTask{label: label}, false)
}

// SuccessWithChildren prints the final task with children and stops the spinner.
func (p *commandProgress) SuccessWithChildren(label string, children []progressChild) {
	p.finish(completedTask{label: label, children: children}, false)
}

// Fail prints the final task with a cross mark and stops the spinner.
func (p *commandProgress) Fail(label string) {
	p.finish(completedTask{label: label, failed: true}, true)
}

func (p *commandProgress) finish(final completedTask, failed bool) {
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

	// Clear the active spinner line, then print pending + final tasks.
	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K")
	for _, t := range steps {
		p.writeTaskBlock(t)
	}
	p.writeTaskBlock(final)
}

// SeparateReport writes a small visual divider after progress completes and
// before a human-readable report is emitted on stdout.
func (p *commandProgress) SeparateReport() {
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

// flushSteps clears the spinner line and writes the given completed tasks.
func (p *commandProgress) flushSteps(steps []completedTask) {
	_, _ = fmt.Fprint(p.writer, "\r\x1b[2K")
	for _, t := range steps {
		p.writeTaskBlock(t)
	}
}

func (p *commandProgress) writeTaskBlock(t completedTask) {
	_, _ = fmt.Fprintln(p.writer, formatCompletedLine(t))
	for i, child := range t.children {
		isLast := i == len(t.children)-1
		_, _ = fmt.Fprintln(p.writer, formatChildLine(child, isLast))
	}
}

func (p *commandProgress) renderActive(frame string) {
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
	title := titleStyle.Width(progressTitleWidth).Render(label)
	if stage != "" {
		return fmt.Sprintf(" %s %s %s", icon, title, stageStyle.Render("["+stage+"]"))
	}
	return fmt.Sprintf(" %s %s", icon, title)
}

func formatCompletedLine(t completedTask) string {
	var icon string
	if t.failed {
		icon = failStyle.Render(progressCrossMark)
	} else {
		icon = successStyle.Render(progressCheckMark)
	}
	title := titleStyle.Render(t.label)
	return fmt.Sprintf(" %s %s", icon, title)
}

func formatChildLine(child progressChild, last bool) string {
	connector := "├──"
	if last {
		connector = "└──"
	}
	if child.Icon != "" {
		var icon string
		switch child.Icon {
		case progressWarningMark:
			icon = warnStyle.Render(child.Icon)
		case progressCrossMark:
			icon = failStyle.Render(child.Icon)
		default:
			icon = successStyle.Render(child.Icon)
		}
		label := lipgloss.NewStyle().Width(progressChildLabelWidth).Render(child.Label)
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
