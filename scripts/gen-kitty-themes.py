#!/usr/bin/env python3
"""Generate internal/tui/kittythemes_data.go from a kitty-themes checkout.

Usage:
  kitten themes --cache-age 0 --dump-theme Dracula >/dev/null
  unzip -qo ~/.cache/kitty/kitty-themes.zip -d /tmp/kitty-themes
  python3 scripts/gen-kitty-themes.py [/tmp/kitty-themes/kitty-themes-master/themes]
"""
import glob, os, re, sys

themes_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kitty-themes/kitty-themes-master/themes"
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out_path = os.path.join(root, "internal/tui/kittythemes_data.go")

entries = []
for path in sorted(glob.glob(os.path.join(themes_dir, "*.conf")), key=lambda p: os.path.basename(p).lower()):
    bid = os.path.basename(path)[:-5]
    name = None
    colors = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("## name:"):
                name = line.split(":", 1)[1].strip()
                continue
            m = re.match(r"^(foreground|background|color\d+)\s+(#[0-9a-fA-F]{6})\b", line)
            if m:
                colors[m.group(1).lower()] = m.group(2).lower()
    if not colors:
        continue
    fg = colors.get("foreground") or colors.get("color7") or colors.get("color15") or "#ffffff"
    dim = colors.get("color8") or colors.get("color0") or "#888888"
    err = colors.get("color1") or "#ff5555"
    ok = colors.get("color2") or "#50fa7b"
    accent = colors.get("color4") or colors.get("color5") or colors.get("color6") or fg
    if not name:
        name = bid.replace("_", " ").replace("-", " ")
    entries.append((bid, name, fg, dim, err, ok, accent))

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

lines = [
    "// Code generated from kitty-themes (kitten themes). DO NOT EDIT.",
    "// Regenerate: python3 scripts/gen-kitty-themes.py",
    "package tui",
    "",
    "// kittyTheme holds display name and colours mapped from a kitty .conf.",
    "type kittyTheme struct {",
    "\tName   string",
    "\tTitle  string",
    "\tDim    string",
    "\tErr    string",
    "\tOk     string",
    "\tAccent string",
    "}",
    "",
    "// kittyThemes is keyed by the kitty theme file id (without .conf).",
    "var kittyThemes = map[string]kittyTheme{",
]
for bid, name, fg, dim, err, ok, accent in entries:
    lines.append(
        f'\t"{esc(bid)}": {{Name: "{esc(name)}", Title: "{fg}", Dim: "{dim}", Err: "{err}", Ok: "{ok}", Accent: "{accent}"}},'
    )
lines += [
    "}",
    "",
    "// kittyThemeIDs is filled in init via sortKittyThemeIDs.",
    "var kittyThemeIDs []string",
    "",
    "func init() {",
    "\tkittyThemeIDs = make([]string, 0, len(kittyThemes))",
    "\tfor id := range kittyThemes {",
    "\t\tkittyThemeIDs = append(kittyThemeIDs, id)",
    "\t}",
    "\tsortKittyThemeIDs()",
    "}",
    "",
]
with open(out_path, "w") as f:
    f.write("\n".join(lines))
print(f"wrote {len(entries)} themes to {out_path}")
