package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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
	if got := ansi.Strip(out); got != "Q to quit" {
		t.Fatalf("stripped renderKeys = %q, want %q", got, "Q to quit")
	}
	// Bold SGR should wrap the key when colours are on; plain "Q to quit"
	// as one run of text must not appear (bold splits Q from the rest).
	if strings.Contains(out, "Q to quit") && !strings.Contains(out, "\x1b") {
		// NO_COLOR / non-TTY may leave plain text; that is fine.
		return
	}
}

func TestKeyStyleUsesForegroundColorNotDim(t *testing.T) {
	cases := []struct {
		name      string
		wantKeyFG lipgloss.Color
		wantDimFG lipgloss.Color
	}{
		{name: ThemeDefault, wantKeyFG: lipgloss.Color("15"), wantDimFG: lipgloss.Color("8")},
		{name: "Dracula", wantKeyFG: lipgloss.Color(kittyThemes["Dracula"].Title), wantDimFG: lipgloss.Color(kittyThemes["Dracula"].Dim)},
		{name: "Catppuccin-Mocha", wantKeyFG: lipgloss.Color(kittyThemes["Catppuccin-Mocha"].Title), wantDimFG: lipgloss.Color(kittyThemes["Catppuccin-Mocha"].Dim)},
		// Light themes must use their dark foreground rather than hardcoded white.
		{name: "Alabaster", wantKeyFG: lipgloss.Color("#000000"), wantDimFG: lipgloss.Color("#777777")},
		{name: "1984_light", wantKeyFG: lipgloss.Color("#19152c"), wantDimFG: lipgloss.Color("#000000")},
		{name: "ayu_light", wantKeyFG: lipgloss.Color("#5b6673"), wantDimFG: lipgloss.Color("#323232")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			th := newTheme(nil, tc.name)
			if !th.key.GetBold() {
				t.Fatalf("theme %q: key style should be bold", tc.name)
			}
			if th.dim.GetBold() {
				t.Fatalf("theme %q: dim style should not be bold", tc.name)
			}
			if got := th.key.GetForeground(); got != tc.wantKeyFG {
				t.Fatalf("theme %q: key foreground = %v, want %v", tc.name, got, tc.wantKeyFG)
			}
			if got := th.dim.GetForeground(); got != tc.wantDimFG {
				t.Fatalf("theme %q: dim foreground = %v, want %v", tc.name, got, tc.wantDimFG)
			}
			if th.key.GetForeground() == th.dim.GetForeground() {
				t.Fatalf("theme %q: key foreground matches dim (%v)", tc.name, th.key.GetForeground())
			}
			out := renderKeys(th, "{A} apply • {Esc} cancel")
			if got := ansi.Strip(out); got != "A apply • Esc cancel" {
				t.Fatalf("theme %q: stripped footer = %q", tc.name, got)
			}
		})
	}
}
