package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func TestHomeViewNoTornANSI(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	h := NewHome(deps)
	m, _ := h.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	h = m.(*Home)
	m, _ = h.Update(tea.KeyMsg{Type: tea.KeyTab}) // Decrypt
	h = m.(*Home)
	v := h.View()
	for _, frag := range []string{"38;2;", "4;38", "[K", "255;0;255"} {
		if strings.Contains(v, frag) {
			t.Fatalf("torn ANSI %q in view:\n%s", frag, v)
		}
	}
	if !strings.Contains(v, "Decrypt") || !strings.Contains(v, "Select a .pbx file to decrypt") {
		t.Fatalf("missing labels:\n%s", v)
	}
	// Active tab underline row should be present as characters, not SGR underline.
	if !strings.Contains(v, "─") {
		t.Fatal("expected ─ underline under active tab")
	}
}

func TestHomeResizeGate(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	h := NewHome(deps)
	m, _ := h.Update(tea.WindowSizeMsg{Width: 20, Height: 10})
	h = m.(*Home)
	v := h.View()
	if !strings.Contains(v, "Terminal too small") || !strings.Contains(v, "720×520px") {
		t.Fatalf("expected resize gate, got:\n%s", v)
	}
	m, _ = h.Update(tea.WindowSizeMsg{Width: minTermWidth, Height: minTermHeight})
	h = m.(*Home)
	v = h.View()
	if strings.Contains(v, "Terminal too small") {
		t.Fatalf("still gated after resize:\n%s", v)
	}
	if !strings.Contains(v, "Select a file to encrypt") {
		t.Fatalf("expected home UI after resize:\n%s", v)
	}
}
