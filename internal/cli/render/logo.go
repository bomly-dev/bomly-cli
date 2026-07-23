package render

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	startupLogoFrameDelay = 70 * time.Millisecond

	// logoFrameCount is the total animation length (~2s at 70ms per frame);
	// the last two frames hold the finished art while the tagline fades in.
	logoFrameCount       = 28
	logoRevealFrameCount = logoFrameCount - 2

	// logoScrambleBand is the width (in columns) of the scramble strip that
	// leads the reveal boundary as it sweeps left to right.
	logoScrambleBand = 5

	bomlyLogoTagline = "Analyze Your Software DNA."
)

// logoMode selects how StartupLogo presents the banner on a TTY.
type logoMode int

const (
	logoAnimate logoMode = iota
	logoStaticColor
	logoStaticPlain
)

// StartupLogo plays a brief Bomly logo animation when w is an attached TTY.
// On non-TTY writers (pipes, files), it is a silent no-op. The animation is
// skipped in favor of a static logo when NO_COLOR (plain), BOMLY_NO_ANIMATION,
// CI, or BOMLY_QUIET (colored) are set. A random animation variant plays each
// run; BOMLY_LOGO pins one by name (reveal, rain, glitch, slide).
func StartupLogo(w io.Writer) {
	file, ok := w.(*os.File)
	if !ok || file == nil {
		return
	}
	if !term.IsTerminal(int(file.Fd())) {
		return
	}

	switch startupLogoMode() {
	case logoStaticPlain:
		_, _ = io.WriteString(file, bomlyLogoStatic(false))
		return
	case logoStaticColor:
		_, _ = io.WriteString(file, bomlyLogoStatic(true))
		return
	}

	frames := selectedLogoFrames()
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

// startupLogoMode applies the environment gates. NO_COLOR follows the
// no-color.org convention (any non-empty value); the remaining variables are
// treated as boolean flags via envFlagSet.
func startupLogoMode() logoMode {
	if os.Getenv("NO_COLOR") != "" {
		return logoStaticPlain
	}
	if envFlagSet("BOMLY_NO_ANIMATION") || envFlagSet("CI") || envFlagSet("BOMLY_QUIET") {
		return logoStaticColor
	}
	return logoAnimate
}

// envFlagSet reports whether the named environment variable is set to a truthy
// value (non-empty and not "0"/"false", case-insensitive).
func envFlagSet(name string) bool {
	value := os.Getenv(name)
	if value == "" {
		return false
	}
	switch strings.ToLower(value) {
	case "0", "false":
		return false
	}
	return true
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

// bomlyLogoStatic renders the finished logo without animation, for
// environments where motion is disabled but stderr is still a TTY.
func bomlyLogoStatic(colored bool) string {
	var b strings.Builder
	for _, line := range bomlyLogoArt() {
		if colored {
			b.WriteString(Style(line, White, Bold))
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	if colored {
		b.WriteString(Style(bomlyLogoTagline, Dim, White))
	} else {
		b.WriteString(bomlyLogoTagline)
	}
	b.WriteString("\n\n")
	return b.String()
}

// logoCellStyle classifies a single animation cell for run-grouped styling.
type logoCellStyle int

const (
	logoCellPlain logoCellStyle = iota
	logoCellRevealed
	logoCellScramble
	logoCellRain
	logoCellRainHead
	logoCellGlitch
)

type logoCell struct {
	glyph rune
	style logoCellStyle
}

// logoVariantNames lists the animation variants in the stable order used for
// random selection; each name keys logoVariantFrames.
var logoVariantNames = []string{"reveal", "rain", "glitch", "slide"}

var logoVariantFrames = map[string]func() []string{
	"reveal": logoRevealFrames,
	"rain":   logoRainFrames,
	"glitch": logoGlitchFrames,
	"slide":  logoSlideFrames,
}

// selectedLogoFrames picks the animation variant for this run: BOMLY_LOGO
// pins one by name (case-insensitive); otherwise a random variant plays.
func selectedLogoFrames() []string {
	if name := strings.ToLower(os.Getenv("BOMLY_LOGO")); name != "" {
		if frames, ok := logoVariantFrames[name]; ok {
			return frames()
		}
	}
	return logoVariantFrames[logoVariantNames[rand.IntN(len(logoVariantNames))]]()
}

// appendLogoFinale adds the shared closing frames: the finished art with the
// tagline fading in (dim, then highlighted).
func appendLogoFinale(frames []string, grid [][]rune) []string {
	revealed := fullyRevealedCells(grid)
	frames = append(frames, renderBomlyLogoFrame(revealed, Style(bomlyLogoTagline, Dim)))
	return append(frames, renderBomlyLogoFrame(revealed, Style(bomlyLogoTagline, Dim, White)))
}

// fullyRevealedCells is the finished logo as styled cells.
func fullyRevealedCells(grid [][]rune) [][]logoCell {
	rows := make([][]logoCell, len(grid))
	for row, line := range grid {
		cells := make([]logoCell, len(line))
		for col, final := range line {
			if final == ' ' {
				cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
			} else {
				cells[col] = logoCell{glyph: final, style: logoCellRevealed}
			}
		}
		rows[row] = cells
	}
	return rows
}

// logoRevealFrames generates the materialize animation: a boundary sweeps
// left to right, preceded by a band of scramble glyphs that resolve into the
// final art.
func logoRevealFrames() []string {
	grid, width := logoRuneGrid(bomlyLogoArt())

	frames := make([]string, 0, logoFrameCount)
	for frame := 0; frame < logoRevealFrameCount; frame++ {
		boundary := (frame + 1) * (width + logoScrambleBand) / logoRevealFrameCount
		frames = append(frames, renderBomlyLogoFrame(revealFrameCells(grid, frame, boundary), ""))
	}
	return appendLogoFinale(frames, grid)
}

// rainGlyphs are code-flavored characters for the matrix-rain variant.
var rainGlyphs = []rune("01<>{}[]#$%&*+=/")

// logoRainFrames generates a matrix-style rain: per-column drops of green
// code glyphs fall down the logo's silhouette, leaving the final art behind.
func logoRainFrames() []string {
	// Speed/phase are tuned so the slowest column (max phase) fully resolves
	// exactly on the last reveal frame: 25*1 - 16 - 3 > 5 (the bottom row).
	const (
		rainTrail      = 3
		rainSpeed      = 1
		rainPhaseRange = 17
	)
	grid, _ := logoRuneGrid(bomlyLogoArt())

	frames := make([]string, 0, logoFrameCount)
	for frame := 0; frame < logoRevealFrameCount; frame++ {
		rows := make([][]logoCell, len(grid))
		for row, line := range grid {
			cells := make([]logoCell, len(line))
			for col, final := range line {
				drop := frame*rainSpeed - int(logoHash(1, uint32(col))%rainPhaseRange)
				switch {
				case final == ' ':
					cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
				case row < drop-rainTrail:
					cells[col] = logoCell{glyph: final, style: logoCellRevealed}
				case row <= drop:
					style := logoCellRain
					if row == drop {
						style = logoCellRainHead
					}
					glyph := logoGlyph(rainGlyphs, 1, uint32(frame), uint32(row), uint32(col))
					cells[col] = logoCell{glyph: glyph, style: style}
				default:
					cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
				}
			}
			rows[row] = cells
		}
		frames = append(frames, renderBomlyLogoFrame(rows, ""))
	}
	return appendLogoFinale(frames, grid)
}

// glitchGlyphs are corruption characters for the glitch variant.
var glitchGlyphs = []rune("▓▒░#%&@?!~")

// logoGlitchFrames generates a signal-stabilizing effect: the full logo is
// visible from the first frame but noisy, and the corruption density decays
// to zero as the signal locks in.
func logoGlitchFrames() []string {
	const maxDensity = 60
	grid, _ := logoRuneGrid(bomlyLogoArt())

	frames := make([]string, 0, logoFrameCount)
	for frame := 0; frame < logoRevealFrameCount; frame++ {
		density := maxDensity * (logoRevealFrameCount - 1 - frame) / (logoRevealFrameCount - 1)
		rows := make([][]logoCell, len(grid))
		for row, line := range grid {
			cells := make([]logoCell, len(line))
			for col, final := range line {
				switch {
				case final == ' ':
					cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
				case int(logoHash(2, uint32(frame), uint32(row), uint32(col))%100) < density:
					style := logoCellScramble
					if logoHash(3, uint32(frame), uint32(row), uint32(col))%4 == 0 {
						style = logoCellGlitch
					}
					glyph := logoGlyph(glitchGlyphs, 2, uint32(frame), uint32(row), uint32(col))
					cells[col] = logoCell{glyph: glyph, style: style}
				default:
					cells[col] = logoCell{glyph: final, style: logoCellRevealed}
				}
			}
			rows[row] = cells
		}
		frames = append(frames, renderBomlyLogoFrame(rows, ""))
	}
	return appendLogoFinale(frames, grid)
}

// logoSlideFrames generates alternating slide-ins: even rows enter from the
// left, odd rows from the right, each dim while moving and bold once landed.
func logoSlideFrames() []string {
	const slideStagger = 2
	grid, width := logoRuneGrid(bomlyLogoArt())
	// Each row starts slideStagger frames after the one above it, and the
	// duration is chosen so the last row lands on the final reveal frame.
	slideDuration := logoRevealFrameCount - slideStagger*(len(grid)-1)

	frames := make([]string, 0, logoFrameCount)
	for frame := 0; frame < logoRevealFrameCount; frame++ {
		rows := make([][]logoCell, len(grid))
		for row, line := range grid {
			cells := make([]logoCell, len(line))
			for col := range line {
				cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
			}
			visible := (frame - slideStagger*row + 1) * width / slideDuration
			if visible < 0 {
				visible = 0
			}
			if visible > width {
				visible = width
			}
			style := logoCellScramble
			if visible == width {
				style = logoCellRevealed
			}
			if row%2 == 0 {
				// Enter from the left: the row's tail is visible at the left edge.
				for idx := 0; idx < visible; idx++ {
					if glyph := line[width-visible+idx]; glyph != ' ' {
						cells[idx] = logoCell{glyph: glyph, style: style}
					}
				}
			} else {
				// Enter from the right: the row's head is visible at the right edge.
				for idx := 0; idx < visible; idx++ {
					if glyph := line[idx]; glyph != ' ' {
						cells[width-visible+idx] = logoCell{glyph: glyph, style: style}
					}
				}
			}
			rows[row] = cells
		}
		frames = append(frames, renderBomlyLogoFrame(rows, ""))
	}
	return appendLogoFinale(frames, grid)
}

// logoRuneGrid converts the art lines to a rune grid padded to a uniform
// width, so the reveal can slice by columns (the box glyphs are multi-byte).
func logoRuneGrid(lines []string) ([][]rune, int) {
	width := 0
	grid := make([][]rune, len(lines))
	for idx, line := range lines {
		grid[idx] = []rune(line)
		if len(grid[idx]) > width {
			width = len(grid[idx])
		}
	}
	for idx := range grid {
		for len(grid[idx]) < width {
			grid[idx] = append(grid[idx], ' ')
		}
	}
	return grid, width
}

// revealFrameCells materializes one frame: columns left of the scramble band
// show the final art, columns inside the band show scramble glyphs, and the
// rest is still blank. Cells that are blank in the final art stay blank so the
// reveal keeps the logo's silhouette.
func revealFrameCells(grid [][]rune, frame, boundary int) [][]logoCell {
	rows := make([][]logoCell, len(grid))
	for row, line := range grid {
		cells := make([]logoCell, len(line))
		for col, final := range line {
			switch {
			case final == ' ':
				cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
			case col < boundary-logoScrambleBand:
				cells[col] = logoCell{glyph: final, style: logoCellRevealed}
			case col < boundary:
				cells[col] = logoCell{glyph: scrambleRune(frame, row, col), style: logoCellScramble}
			default:
				cells[col] = logoCell{glyph: ' ', style: logoCellPlain}
			}
		}
		rows[row] = cells
	}
	return rows
}

// scrambleGlyphs are block-family glyphs whose visual weight matches the art,
// so the scramble band reads as the logo materializing rather than noise.
var scrambleGlyphs = []rune("░▒▓█▌▐▀▄")

// scrambleRune picks the reveal variant's scramble glyph per (frame, row, col).
func scrambleRune(frame, row, col int) rune {
	return logoGlyph(scrambleGlyphs, 0, uint32(frame), uint32(row), uint32(col))
}

// logoHash is a deterministic FNV-1a mix over the given values, so animation
// frames are stable across runs and testable.
func logoHash(values ...uint32) uint32 {
	const (
		fnvOffset32 = 2166136261
		fnvPrime32  = 16777619
		logoSeed    = 0x9e3779b9
	)
	hash := uint32(fnvOffset32)
	hash ^= logoSeed
	hash *= fnvPrime32
	for _, v := range values {
		hash ^= v
		hash *= fnvPrime32
	}
	return hash
}

// logoGlyph picks a deterministic pseudo-random glyph from set.
func logoGlyph(set []rune, values ...uint32) rune {
	return set[logoHash(values...)%uint32(len(set))]
}

// renderBomlyLogoFrame emits one frame: each line erased and rewritten, with
// consecutive same-style cells grouped into a single escape-wrapped run.
// tagline is passed pre-styled ("" on reveal frames).
func renderBomlyLogoFrame(rows [][]logoCell, tagline string) string {
	var b strings.Builder
	for _, cells := range rows {
		b.WriteString("\x1b[2K\r")
		b.WriteString(styledLogoRow(cells))
		b.WriteByte('\n')
	}
	b.WriteString("\x1b[2K\r")
	b.WriteString(tagline)
	b.WriteByte('\n')
	b.WriteString("\x1b[2K\r\n")
	return b.String()
}

// styledLogoRow groups consecutive cells with the same style into runs so
// each run costs one escape sequence instead of one per rune.
func styledLogoRow(cells []logoCell) string {
	var b strings.Builder
	var run []rune
	current := logoCellPlain
	flush := func() {
		if len(run) == 0 {
			return
		}
		text := string(run)
		switch current {
		case logoCellRevealed:
			b.WriteString(Style(text, White, Bold))
		case logoCellScramble:
			b.WriteString(Style(text, Dim))
		case logoCellRain:
			b.WriteString(Style(text, Green))
		case logoCellRainHead:
			b.WriteString(Style(text, Green, Bold))
		case logoCellGlitch:
			b.WriteString(Style(text, Cyan))
		default:
			b.WriteString(text)
		}
		run = run[:0]
	}
	for _, cell := range cells {
		if cell.style != current {
			flush()
			current = cell.style
		}
		run = append(run, cell.glyph)
	}
	flush()
	return b.String()
}
