package cli

import (
	"github.com/spf13/cobra"
)

func newStatusCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show mode, 2FA state, keystore path and version",
		Args:  exactArgs(0, "usage: pillarbox status"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runStatus()
		},
	}
}

// runStatus prints no secret, seed or key, FR-13.
func (d *Deps) runStatus() error {
	st, err := d.loadSettings()
	if err != nil {
		return err
	}
	keyType := string(st.KeyType)
	if keyType == "" {
		keyType = "(not set)"
	}
	d.printf("key type: %s\nauth-encrypt: %t\nsettings: %s\nversion: %s\n", keyType, st.AuthEncrypt, d.Settings.Path(), Version)
	return nil
}
