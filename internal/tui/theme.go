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

// newRenderer is a var so tests can observe color handling. termenv honours
// NO_COLOR when the renderer is built, so styles degrade to plain text.
var newRenderer = func(w io.Writer) *lipgloss.Renderer {
	return lipgloss.NewRenderer(w)
}

type theme struct {
	name      string
	title     lipgloss.Style
	dim       lipgloss.Style
	key       lipgloss.Style // foreground colour, bold — shortcut glyphs in footers
	selected  lipgloss.Style // bold focus row in lists
	errS      lipgloss.Style
	ok        lipgloss.Style
	tab       lipgloss.Style
	tabActive lipgloss.Style
	accent    lipgloss.Style
	box       lipgloss.Style
}

func newTheme(w io.Writer, name string) theme {
	r := newRenderer(w)
	id := NormalizeTheme(name)
	p := paletteFor(id)
	titleColor := lipgloss.Color(p.title)
	dimColor := lipgloss.Color(p.dim)
	accent := lipgloss.Color(p.accent)
	return theme{
		name:      id,
		title:     r.NewStyle().Bold(true).Foreground(titleColor),
		dim:       r.NewStyle().Foreground(dimColor),
		key:       r.NewStyle().Bold(true).Foreground(titleColor),
		selected:  r.NewStyle().Bold(true).Foreground(lipgloss.Color(p.selected)),
		errS:      r.NewStyle().Foreground(lipgloss.Color(p.err)),
		ok:        r.NewStyle().Foreground(lipgloss.Color(p.ok)),
		tab:       r.NewStyle().Foreground(lipgloss.Color(p.tab)),
		tabActive: r.NewStyle().Bold(true).Foreground(accent),
		accent:    r.NewStyle().Foreground(accent),
		box: r.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(accent).
			Padding(0, 1),
	}
}

// renderKeys styles {Key} markers as bold foreground shortcuts in dim help text.
// Example: "{Q} to quit" → bold bright Q, dim " to quit".
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
