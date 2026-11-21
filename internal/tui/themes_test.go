package tui

import (
	"testing"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func TestNormalizeTheme(t *testing.T) {
	cases := map[string]string{
		"":           ThemeDefault,
		"default":    ThemeDefault,
		"Dracula":    "Dracula",
		"dracula":    "Dracula",
		"catppuccin": "Catppuccin-Mocha",
		"jade":       "osaka-jade",
		"nope":       ThemeDefault,
	}
	for in, want := range cases {
		if got := NormalizeTheme(in); got != want {
			t.Fatalf("NormalizeTheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestThemeValid(t *testing.T) {
	if !ThemeValid("") || !ThemeValid("dracula") || !ThemeValid("Catppuccin-Mocha") {
		t.Fatal("expected known themes to be valid")
	}
	if ThemeValid("nope") {
		t.Fatal("unknown theme should be invalid")
	}
}

func TestKittyCatalogLoaded(t *testing.T) {
	if len(kittyThemes) < 100 {
		t.Fatalf("kittyThemes = %d, want hundreds from kitten themes", len(kittyThemes))
	}
	if len(themeNames) != 1+len(kittyThemeIDs) {
		t.Fatalf("themeNames = %d, kittyThemeIDs = %d", len(themeNames), len(kittyThemeIDs))
	}
	if themeNames[0] != ThemeDefault {
		t.Fatalf("first theme = %q, want default", themeNames[0])
	}
	th := newTheme(nil, "Dracula")
	if th.name != "Dracula" {
		t.Fatalf("newTheme Dracula name = %q", th.name)
	}
}

func TestPaletteForDefault(t *testing.T) {
	p := paletteFor(ThemeDefault)
	if p.accent != "201" {
		t.Fatalf("default accent = %q, want 201", p.accent)
	}
}

func TestApplyDraculaViaSettingsStore(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	h := NewHome(deps)
	h.settings.Theme = "Dracula"
	if err := deps.Settings.Save(h.settings); err != nil {
		t.Fatal(err)
	}
	h.applyTheme(h.settings.Theme)
	if h.th.name != "Dracula" {
		t.Fatalf("theme = %q, want Dracula", h.th.name)
	}
	st, err := deps.Settings.Load()
	if err != nil || st.Theme != "Dracula" {
		t.Fatalf("saved theme = %+v, %v", st, err)
	}
}
