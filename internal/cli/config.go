package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func newConfigCmd(d *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Change settings",
		Args:  exactArgs(0, "usage: pillarbox config set gate-encrypt true|false | key-type password|pin|password+2fa|pin+2fa"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return &exitError{ExitUsage, "usage: pillarbox config set gate-encrypt true|false | key-type MODE"}
		},
	}
	c.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a setting",
		Args:  exactArgs(2, "usage: pillarbox config set gate-encrypt true|false | key-type MODE"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runConfigSet(args[0], args[1])
		},
	})
	return c
}

func (d *Deps) runConfigSet(key, value string) error {
	st, err := d.loadSettings()
	if err != nil {
		return err
	}
	switch key {
	case "gate-encrypt":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return &exitError{ExitUsage, "value must be true or false"}
		}
		st.GateEncrypt = v
	case "key-type":
		m := keystore.Mode(value)
		if !m.Valid() {
			return &exitError{ExitUsage, "invalid key type; want password, pin, password+2fa or pin+2fa"}
		}
		st.KeyType = m
	default:
		return &exitError{ExitUsage, "unknown setting; supported: gate-encrypt, key-type"}
	}
	if err := d.Settings.Save(st); err != nil {
		return &exitError{ExitOther, "could not save settings"}
	}
	if !d.opts.quiet {
		d.printf("%s set\n", key)
	}
	return nil
}
