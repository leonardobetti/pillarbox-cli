package tui

import (
	"bytes"

	"github.com/mdp/qrterminal/v3"
	"rsc.io/qr"
)

// renderQR renders the otpauth URI as a terminal QR code using half-block
// glyphs, so it stays scannable with NO_COLOR and on any background.
func renderQR(uri string) string {
	var buf bytes.Buffer
	qrterminal.GenerateWithConfig(uri, qrterminal.Config{
		Level:          qr.L,
		Writer:         &buf,
		HalfBlocks:     true,
		BlackChar:      "█",
		WhiteChar:      " ",
		BlackWhiteChar: "▀",
		WhiteBlackChar: "▄",
		QuietZone:      1,
	})
	return buf.String()
}

// copyToClipboard writes text through Deps.CopyText and reports the outcome
// in one line. A missing clipboard utility is a message, not a crash.
func copyToClipboard(d *Deps, text string) string {
	fn := d.CopyText
	if fn == nil {
		return "clipboard unavailable"
	}
	if err := fn(text); err != nil {
		return "clipboard unavailable"
	}
	return "copied 2FA URI to clipboard"
}
