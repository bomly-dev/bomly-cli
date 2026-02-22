package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const startupLogoFrameDelay = 90 * time.Millisecond

func maybeRenderStartupLogo(w io.Writer) {
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
		"\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557   \u2588\u2588\u2557",
		"\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551  \u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d",
		"\u2588\u2588\u2588\u2588\u2588\u2588\u2566\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2588\u2588\u2554\u2588\u2588\u2551\u2588\u2588\u2551   \u255a\u2588\u2588\u2588\u2588\u2554\u255d ",
		"\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2551    \u255a\u2588\u2588\u2554\u255d  ",
		"\u2588\u2588\u2588\u2588\u2588\u2588\u2566\u255d\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551 \u255a\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551   ",
		"\u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d     \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d   ",
	}
}

func bomlyLogoFrames() []string {
	art := bomlyLogoArt()
	palette := [][]string{
		{ansiDim, ansiWhite, ansiDim, ansiWhite, ansiDim, ansiDim},
		{ansiDim, ansiDim, ansiWhite, ansiDim, ansiDim, ansiDim},
		{ansiWhite, ansiDim, ansiWhite, ansiDim, ansiWhite, ansiDim},
		{ansiWhite, ansiWhite, ansiDim, ansiWhite, ansiWhite, ansiDim},
		{ansiWhite, ansiWhite, ansiWhite, ansiDim, ansiWhite, ansiDim},
		{ansiDim, ansiWhite, ansiWhite, ansiWhite, ansiDim, ansiDim},
		{ansiWhite, ansiDim, ansiWhite, ansiWhite, ansiWhite, ansiDim},
		{ansiWhite, ansiWhite, ansiWhite, ansiWhite, ansiWhite, ansiDim},
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
		color := ansiCyan
		if idx < len(colors) && colors[idx] != "" {
			color = colors[idx]
		}
		b.WriteString(ansiStyled(line, color, ansiBold))
		b.WriteByte('\n')
	}
	_, _ = b.WriteString("\x1b[2K\r")
	b.WriteString(ansiStyled("SBOM clarity with momentum.", ansiDim, ansiWhite))
	b.WriteByte('\n')
	_, _ = b.WriteString("\x1b[2K\r")
	b.WriteByte('\n')
	return b.String()
}

func startupLogoHelpFunc(root *cobra.Command) func(*cobra.Command, []string) {
	defaultHelp := root.HelpFunc()
	return func(cmd *cobra.Command, args []string) {
		if cmd == root {
			maybeRenderStartupLogo(cmd.ErrOrStderr())
		}
		defaultHelp(cmd, args)
	}
}
