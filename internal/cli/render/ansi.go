// Package render owns CLI presentation primitives: ANSI styling, the startup logo,
// and SBOM output spec parsing. Higher-level scan / diff / explain text rendering
// remains in the cli package for now (it depends on many cli-internal helpers);
// extracting it is tracked as follow-up work.
package render

import "strings"

// ANSI escape sequences reused across cli text rendering and the interactive TUI.
const (
	Reset   = "\x1b[0m"
	Black   = "\x1b[30m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Blue    = "\x1b[34m"
	Magenta = "\x1b[34m"
	Cyan    = "\x1b[36m"
	White   = "\x1b[37m"
	Gray    = "\x1b[90m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"

	BgBlue    = "\x1b[44m"
	BgCyan    = "\x1b[44m"
	BgGreen   = "\x1b[42m"
	BgRed     = "\x1b[41m"
	BgYellow  = "\x1b[43m"
	BgMagenta = "\x1b[100m"
)

// Wrap returns value bracketed by the given color/style and a reset.
func Wrap(value, color string) string {
	if value == "" || color == "" {
		return value
	}
	return color + value + Reset
}

// Style applies one or more ANSI codes to value.
func Style(value string, codes ...string) string {
	if value == "" || len(codes) == 0 {
		return value
	}
	return strings.Join(codes, "") + value + Reset
}

// ColorizeGraphTree highlights cycle/shared markers in dependency tree output.
func ColorizeGraphTree(value string) string {
	value = strings.ReplaceAll(value, "(cycle)", Wrap("(cycle)", Red))
	value = strings.ReplaceAll(value, "(shared)", Wrap("(shared)", Yellow))
	return value
}

// StripANSI removes any CSI escape sequences from value.
func StripANSI(value string) string {
	var out strings.Builder
	inEscape := false
	for idx := 0; idx < len(value); idx++ {
		ch := value[idx]
		if inEscape {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b && idx+1 < len(value) && value[idx+1] == '[' {
			inEscape = true
			idx++
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}
