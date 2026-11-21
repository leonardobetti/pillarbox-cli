package cli

import (
	"github.com/spf13/cobra"
)

func newStatusCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show default key type, 2FA setup, settings path and version",
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
	shared2FA := "not set"
	if d.TOTPStore != nil {
		if ok, err := d.TOTPStore.Exists(); err == nil && ok {
			shared2FA = "configured"
		}
	}
	device := "absent"
	if d.DevStore != nil {
		if _, err := d.DevStore.Load(); err == nil {
			device = "present"
		}
	}
	d.printf("default key type: %s\nrequire auth to encrypt: %t\nshared 2fa: %s\ndevice secret: %s\nsettings: %s\nversion: %s\n",
		keyType, st.AuthEncrypt, shared2FA, device, d.Settings.Path(), Version)
	return nil
}
