package cli

import "strings"

const (
	ansiReset   = "\x1b[0m"
	ansiBlack   = "\x1b[30m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[34m"
	ansiCyan    = "\x1b[36m"
	ansiWhite   = "\x1b[37m"
	ansiGray    = "\x1b[90m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"

	ansiBgBlue    = "\x1b[44m"
	ansiBgCyan    = "\x1b[44m"
	ansiBgGreen   = "\x1b[42m"
	ansiBgRed     = "\x1b[41m"
	ansiBgYellow  = "\x1b[43m"
	ansiBgMagenta = "\x1b[100m"
)

func ansiWrap(value, color string) string {
	if value == "" || color == "" {
		return value
	}
	return color + value + ansiReset
}

func colorizeGraphTree(value string) string {
	value = strings.ReplaceAll(value, "(cycle)", ansiWrap("(cycle)", ansiRed))
	value = strings.ReplaceAll(value, "(shared)", ansiWrap("(shared)", ansiYellow))
	return value
}

func ansiStyled(value string, codes ...string) string {
	if value == "" || len(codes) == 0 {
		return value
	}
	return strings.Join(codes, "") + value + ansiReset
}

func stripANSI(value string) string {
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
