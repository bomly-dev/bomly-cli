package cli

import "github.com/bomly-dev/bomly-cli/internal/cli/render"

// ANSI escape sequences are owned by internal/cli/render. They're aliased here so
// existing cli/tui call sites keep working without churn; new code should use the
// render package directly.
const (
	ansiReset   = render.Reset
	ansiBlack   = render.Black
	ansiRed     = render.Red
	ansiGreen   = render.Green
	ansiYellow  = render.Yellow
	ansiBlue    = render.Blue
	ansiMagenta = render.Magenta
	ansiCyan    = render.Cyan
	ansiWhite   = render.White
	ansiGray    = render.Gray
	ansiBold    = render.Bold
	ansiDim     = render.Dim

	ansiBgBlue    = render.BgBlue
	ansiBgCyan    = render.BgCyan
	ansiBgGreen   = render.BgGreen
	ansiBgRed     = render.BgRed
	ansiBgYellow  = render.BgYellow
	ansiBgMagenta = render.BgMagenta
)

func ansiWrap(value, color string) string             { return render.Wrap(value, color) }
func ansiStyled(value string, codes ...string) string { return render.Style(value, codes...) }
func colorizeGraphTree(value string) string           { return render.ColorizeGraphTree(value) }
func stripANSI(value string) string                   { return render.StripANSI(value) }
