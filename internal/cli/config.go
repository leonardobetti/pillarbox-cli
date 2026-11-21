package cli

import (
	"strconv"

	"github.com/spf13/cobra"
)

func newConfigCmd(d *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Change settings",
		Args:  exactArgs(0, "usage: pillarbox config set gate-encrypt true|false"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return &exitError{ExitUsage, "usage: pillarbox config set gate-encrypt true|false"}
		},
	}
	c.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a setting",
		Args:  exactArgs(2, "usage: pillarbox config set gate-encrypt true|false"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runConfigSet(args[0], args[1])
		},
	})
	return c
}

func (d *Deps) runConfigSet(key, value string) error {
	if key != "gate-encrypt" {
		return &exitError{ExitUsage, "unknown setting; supported: gate-encrypt"}
	}
	v, err := strconv.ParseBool(value)
	if err != nil {
		return &exitError{ExitUsage, "value must be true or false"}
	}
	ks, err := d.loadKeystore()
	if err != nil {
		return err
	}
	ks.Policy.GateEncrypt = v
	if err := d.Store.Save(ks); err != nil {
		return &exitError{ExitOther, "could not save keystore"}
	}
	if !d.opts.quiet {
		d.printf("gate-encrypt = %t\n", v)
	}
	return nil
}
