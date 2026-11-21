package tui

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Layout cell budget. minTerm* is the smallest window we render the full UI
// for — about 800×800 CSS/device pixels at a typical monospace cell
// (~10×20px). Below that, Home shows a resize hint instead of a broken frame.
const (
	maxWidth      = 78
	maxHeight     = 24
	minTermWidth  = 80
	minTermHeight = 40
)

// Magenta accent (ANSI 201). Avoid truecolor here: shorter sequences and
// fewer surprises when a view is width-capped.
const accentColor = lipgloss.Color("201")

// newRenderer is a var so tests can observe color handling. termenv honours
// NO_COLOR when the renderer is built, so styles degrade to plain text.
var newRenderer = func(w io.Writer) *lipgloss.Renderer {
	return lipgloss.NewRenderer(w)
}

type theme struct {
	title     lipgloss.Style
	dim       lipgloss.Style
	key       lipgloss.Style // dim colour, bold — shortcut glyphs in footers
	selected  lipgloss.Style // bold focus row in lists
	errS      lipgloss.Style
	ok        lipgloss.Style
	tab       lipgloss.Style
	tabActive lipgloss.Style
	accent    lipgloss.Style
	box       lipgloss.Style
}

func newTheme(w io.Writer) theme {
	r := newRenderer(w)
	dimColor := lipgloss.Color("8")
	return theme{
		title:     r.NewStyle().Bold(true).Foreground(lipgloss.Color("15")),
		dim:       r.NewStyle().Foreground(dimColor),
		key:       r.NewStyle().Bold(true).Foreground(dimColor),
		selected:  r.NewStyle().Bold(true).Foreground(lipgloss.Color("15")),
		errS:      r.NewStyle().Foreground(lipgloss.Color("9")),
		ok:        r.NewStyle().Foreground(lipgloss.Color("10")),
		tab:       r.NewStyle().Foreground(lipgloss.Color("15")),
		tabActive: r.NewStyle().Bold(true).Foreground(accentColor),
		accent:    r.NewStyle().Foreground(accentColor),
		box: r.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(accentColor).
			Padding(0, 1),
	}
}

// renderKeys styles {Key} markers as bold shortcuts in dim help text.
// Example: "{Q} to quit" → bold Q, dim " to quit".
func renderKeys(th theme, s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			b.WriteString(th.dim.Render(s))
			return b.String()
		}
		if i > 0 {
			b.WriteString(th.dim.Render(s[:i]))
		}
		rest := s[i+1:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			b.WriteString(th.dim.Render(s[i:]))
			return b.String()
		}
		b.WriteString(th.key.Render(rest[:j]))
		s = rest[j+1:]
	}
}

// fit caps the view to width×height without slicing ANSI sequences. The old
// rune-slice wrap cut through SGR codes and printed garbage like
// "4;38;2;255;0;255;4mpt" into the tab row.
func fit(s string, width, height int) string {
	if width <= 0 {
		width = maxWidth
	}
	if height <= 0 {
		height = maxHeight
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		wrapped := ansi.Wrap(line, width, "")
		out = append(out, strings.Split(wrapped, "\n")...)
	}
	if len(out) > height {
		out = out[:height]
	}
	return strings.Join(out, "\n")
}
