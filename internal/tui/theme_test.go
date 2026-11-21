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
