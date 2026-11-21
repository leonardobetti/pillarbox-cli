package tui

import (
	"sort"
	"strings"
)

// ThemeDefault is the original Pillarbox ANSI magenta look.
const ThemeDefault = "default"

// themeNames is Default plus every kitty theme id, for the picker.
var themeNames []string

func init() {
	themeNames = make([]string, 0, 1+len(kittyThemeIDs))
	themeNames = append(themeNames, ThemeDefault)
	themeNames = append(themeNames, kittyThemeIDs...)
}

func sortKittyThemeIDs() {
	sort.Slice(kittyThemeIDs, func(i, j int) bool {
		a, b := kittyThemes[kittyThemeIDs[i]], kittyThemes[kittyThemeIDs[j]]
		an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if an != bn {
			return an < bn
		}
		return strings.ToLower(kittyThemeIDs[i]) < strings.ToLower(kittyThemeIDs[j])
	})
}

// palette is the colour set for one named theme. Values are lipgloss color
// strings (ANSI index or #RRGGBB).
type palette struct {
	title    string
	dim      string
	selected string
	err      string
	ok       string
	tab      string
	accent   string
}

func themeDisplayName(id string) string {
	id = NormalizeTheme(id)
	if id == ThemeDefault {
		return "Default"
	}
	if kt, ok := lookupKittyTheme(id); ok {
		return kt.Name
	}
	return id
}

// themeAliases maps older Pillarbox theme ids onto kitty file ids.
var themeAliases = map[string]string{
	"dracula":    "Dracula",
	"catppuccin": "Catppuccin-Mocha",
	"capuchin":   "Catppuccin-Mocha",
	"cappuccino": "Catppuccin-Mocha",
	"jade":       "osaka-jade",
	"jade-horse": "osaka-jade",
}

func lookupKittyTheme(id string) (kittyTheme, bool) {
	if kt, ok := kittyThemes[id]; ok {
		return kt, true
	}
	// Case-insensitive file id match.
	lower := strings.ToLower(id)
	for k, kt := range kittyThemes {
		if strings.ToLower(k) == lower {
			return kt, true
		}
	}
	return kittyTheme{}, false
}

func resolveThemeID(id string) (string, bool) {
	s := strings.TrimSpace(id)
	if s == "" || strings.EqualFold(s, ThemeDefault) {
		return ThemeDefault, true
	}
	if alias, ok := themeAliases[strings.ToLower(s)]; ok {
		s = alias
	}
	if _, ok := lookupKittyTheme(s); ok {
		// Return canonical map key.
		if _, ok := kittyThemes[s]; ok {
			return s, true
		}
		lower := strings.ToLower(s)
		for k := range kittyThemes {
			if strings.ToLower(k) == lower {
				return k, true
			}
		}
	}
	// Match by display name.
	want := strings.ToLower(s)
	for k, kt := range kittyThemes {
		if strings.ToLower(kt.Name) == want {
			return k, true
		}
	}
	return "", false
}

// NormalizeTheme maps a settings value to a known theme id. Empty means
// Default. Unknown names fall back to Default.
func NormalizeTheme(id string) string {
	if key, ok := resolveThemeID(id); ok {
		return key
	}
	return ThemeDefault
}

// ThemeValid reports whether id is empty or a known theme name.
func ThemeValid(id string) bool {
	_, ok := resolveThemeID(id)
	return ok
}

func paletteFor(id string) palette {
	id = NormalizeTheme(id)
	if id == ThemeDefault {
		return palette{
			title: "15", dim: "8", selected: "15",
			err: "9", ok: "10", tab: "15", accent: "201",
		}
	}
	kt, ok := lookupKittyTheme(id)
	if !ok {
		return paletteFor(ThemeDefault)
	}
	return palette{
		title: kt.Title, dim: kt.Dim, selected: kt.Title,
		err: kt.Err, ok: kt.Ok, tab: kt.Title, accent: kt.Accent,
	}
}
