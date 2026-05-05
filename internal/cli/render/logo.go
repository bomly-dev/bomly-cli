package render

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const startupLogoFrameDelay = 90 * time.Millisecond

// StartupLogo plays a brief Bomly logo animation when w is an attached TTY.
// On non-TTY writers (pipes, files), it is a silent no-op.
func StartupLogo(w io.Writer) {
	file, ok := w.(*os.File)
	if !ok || file == nil {
		return
	}
	if !term.IsTerminal(int(file.Fd())) {
		return
	}

	frames := bomlyLogoFrames()
	if len(frames) == 0 {
		return
	}

	frameLines := bomlyLogoFrameLineCount()
	_, _ = io.WriteString(file, strings.Repeat("\n", frameLines))
	_, _ = io.WriteString(file, fmt.Sprintf("\x1b[%dA", frameLines))
	_, _ = io.WriteString(file, "\x1b[?25l")
	defer func() {
		_, _ = io.WriteString(file, "\x1b[?25h")
	}()

	for idx, frame := range frames {
		if idx > 0 {
			_, _ = io.WriteString(file, fmt.Sprintf("\x1b[%dA", frameLines))
		}
		_, _ = io.WriteString(file, frame)
		if idx < len(frames)-1 {
			time.Sleep(startupLogoFrameDelay)
		}
	}
}

func bomlyLogoFrameLineCount() int {
	return len(bomlyLogoArt()) + 2
}

// bomlyLogoArt returns the lines of the Bomly logo art, which is used for the startup animation.
//
//	"██████╗  ██████╗ ███╗   ███╗██╗  ██╗   ██╗",
//	"██╔══██╗██╔═══██╗████╗ ████║██║  ╚██╗ ██╔╝",
//	"██████╦╝██║   ██║██╔████╔██║██║   ╚████╔╝ ",
//	"██╔══██╗██║   ██║██║╚██╔╝██║██║    ╚██╔╝  ",
//	"██████╦╝╚██████╔╝██║ ╚═╝ ██║███████╗██║   ",
//	"╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝   ",
func bomlyLogoArt() []string {
	return []string{
		"██████╗  ██████╗ ███╗   ███╗██╗  ██╗   ██╗",
		"██╔══██╗██╔═══██╗████╗ ████║██║  ╚██╗ ██╔╝",
		"██████╦╝██║   ██║██╔████╔██║██║   ╚████╔╝ ",
		"██╔══██╗██║   ██║██║╚██╔╝██║██║    ╚██╔╝  ",
		"██████╦╝╚██████╔╝██║ ╚═╝ ██║███████╗██║   ",
		"╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝   ",
	}
}

func bomlyLogoFrames() []string {
	art := bomlyLogoArt()
	palette := [][]string{
		{Dim, White, Dim, White, Dim, Dim},
		{Dim, Dim, White, Dim, Dim, Dim},
		{White, Dim, White, Dim, White, Dim},
		{White, White, Dim, White, White, Dim},
		{White, White, White, Dim, White, Dim},
		{Dim, White, White, White, Dim, Dim},
		{White, Dim, White, White, White, Dim},
		{White, White, White, White, White, Dim},
	}

	frames := make([]string, 0, len(palette))
	for _, colors := range palette {
		frames = append(frames, renderBomlyLogoFrame(art, colors))
	}
	return frames
}

func renderBomlyLogoFrame(lines, colors []string) string {
	var b strings.Builder
	for idx, line := range lines {
		_, _ = b.WriteString("\x1b[2K\r")
		color := Cyan
		if idx < len(colors) && colors[idx] != "" {
			color = colors[idx]
		}
		b.WriteString(Style(line, color, Bold))
		b.WriteByte('\n')
	}
	_, _ = b.WriteString("\x1b[2K\r")
	b.WriteString(Style("SBOM clarity with momentum.", Dim, White))
	b.WriteByte('\n')
	_, _ = b.WriteString("\x1b[2K\r")
	b.WriteByte('\n')
	return b.String()
}
