package cli

import (
	"github.com/spf13/cobra"
)

func newExportKeyCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "export-key",
		Short: "Print the recovery key after authentication",
		Args:  exactArgs(0, "usage: pillarbox export-key"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runExportKey()
		},
	}
}

// runExportKey authenticates and prints the age identity, PRD 6.6.
func (d *Deps) runExportKey() error {
	ks, err := d.loadKeystore()
	if err != nil {
		return err
	}
	identityBytes, _, err := d.authenticate(ks)
	if err != nil {
		return err
	}
	d.println(string(identityBytes))
	return nil
}
