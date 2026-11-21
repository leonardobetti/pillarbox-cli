package tui

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The layout fits 80 by 24, PRD section 11.
const (
	maxWidth  = 78
	maxHeight = 24
)

// Magenta accent from the UI proposal (active tab, underline, content border).
const accentColor = lipgloss.Color("#ff00ff")

// newRenderer is a var so tests can observe color handling. termenv honours
// NO_COLOR when the renderer is built, so styles degrade to plain text.
var newRenderer = func(w io.Writer) *lipgloss.Renderer {
	return lipgloss.NewRenderer(w)
}

type theme struct {
	title     lipgloss.Style
	dim       lipgloss.Style
	errS      lipgloss.Style
	ok        lipgloss.Style
	tab       lipgloss.Style
	tabActive lipgloss.Style
	box       lipgloss.Style
	cursor    lipgloss.Style
}

func newTheme(w io.Writer) theme {
	r := newRenderer(w)
	return theme{
		title:     r.NewStyle().Bold(true).Foreground(lipgloss.Color("15")),
		dim:       r.NewStyle().Foreground(lipgloss.Color("8")),
		errS:      r.NewStyle().Foreground(lipgloss.Color("9")),
		ok:        r.NewStyle().Foreground(lipgloss.Color("10")),
		tab:       r.NewStyle().Foreground(lipgloss.Color("15")),
		tabActive: r.NewStyle().Foreground(accentColor).Bold(true).Underline(true),
		box: r.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(accentColor).
			Padding(0, 1),
		cursor: r.NewStyle().Foreground(lipgloss.Color("15")),
	}
}

// fit hard-wraps s to width and caps it at height lines so every screen stays
// inside 80 by 24.
func fit(s string, width, height int) string {
	if width <= 0 {
		width = maxWidth
	}
	if height <= 0 {
		height = maxHeight
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		for len([]rune(line)) > width {
			r := []rune(line)
			out = append(out, string(r[:width]))
			line = string(r[width:])
		}
		out = append(out, line)
	}
	if len(out) > height {
		out = out[:height]
	}
	return strings.Join(out, "\n")
}
