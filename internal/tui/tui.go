package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

// Deps wires the core services into the TUI, mirroring cli.Deps. Tests inject
// the real implementations rooted in temp dirs, or fakes for TOTP.
type Deps struct {
	Settings  keystore.SettingsStore
	Wrapper   keystore.Wrapper
	KDF       auth.KDF
	TOTP      auth.TOTP
	DevStore  auth.DeviceSecretStore
	TOTPStore auth.TOTPSeedStore
	Vault     vault.Vault
	Version   string
	StartDir  string             // picker start directory, default "."
	CopyText  func(string) error // clipboard write, e.g. atotto/clipboard
}

// RunHome runs the home menu, PRD 8.2, and returns the final model.
func RunHome(d *Deps) (tea.Model, error) {
	return tea.NewProgram(NewHome(d), tea.WithAltScreen()).Run()
}
