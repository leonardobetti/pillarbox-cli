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
	ks, err := d.loadKeystore()
	if err != nil {
		return err
	}
	twoFA := "off"
	if ks.WrappedTOTPSeed != nil {
		twoFA = "on"
	}
	d.printf("mode: %s\n2fa: %s\nkeystore: %s\nversion: %s\n", ks.Mode, twoFA, d.Store.Path(), Version)
	return nil
}
