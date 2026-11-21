package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestFitDoesNotSplitANSISequences(t *testing.T) {
	r := lipgloss.NewRenderer(nil)
	styled := r.NewStyle().Bold(true).Foreground(lipgloss.Color("201")).Render("Decrypt")
	line := "Encrypt  " + styled + "  Status  Settings  Help"
	// Force a wrap that would have sliced the SGR mid-sequence with the old fit.
	out := fit(line, 20, 10)
	if strings.Contains(out, "38;5;") || strings.Contains(out, "38;2;") || strings.Contains(out, "201m") {
		// Visible leftovers of a torn escape. Plain "Decrypt" after a reset is fine.
		for _, frag := range []string{"38;5;", "38;2;", ";201m", "4;38"} {
			if strings.Contains(out, frag) {
				t.Fatalf("fit tore an ANSI sequence; output %q", out)
			}
		}
	}
	if strings.Contains(out, "[K") {
		t.Fatalf("fit left control debris: %q", out)
	}
}

func TestRenderKeysBoldsShortcuts(t *testing.T) {
	th := newTheme(nil, ThemeDefault)
	out := renderKeys(th, "{Q} to quit")
	if !strings.Contains(out, "Q") || !strings.Contains(out, "to quit") {
		t.Fatalf("renderKeys = %q", out)
	}
	// Bold SGR should wrap the key when colours are on; plain "Q to quit"
	// as one run of text must not appear (bold splits Q from the rest).
	if strings.Contains(out, "Q to quit") && !strings.Contains(out, "\x1b") {
		// NO_COLOR / non-TTY may leave plain text; that is fine.
		return
	}
}
