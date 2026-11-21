package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/tui"
)

func newConfigCmd(d *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Change settings",
		Args:  exactArgs(0, "usage: pillarbox config set auth-encrypt|key-type|theme <value>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return &exitError{ExitUsage, "usage: pillarbox config set auth-encrypt|key-type|theme <value>"}
		},
	}
	c.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a setting",
		Args:  exactArgs(2, "usage: pillarbox config set auth-encrypt|key-type|theme <value>"),
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
	case "auth-encrypt":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return &exitError{ExitUsage, "value must be true or false"}
		}
		st.AuthEncrypt = v
	case "key-type":
		m := keystore.Mode(value)
		if !m.Valid() {
			return &exitError{ExitUsage, "invalid key type; want password, pin, password+2fa or pin+2fa"}
		}
		st.KeyType = m
	case "theme":
		if !tui.ThemeValid(value) {
			return &exitError{ExitUsage, "invalid theme; want default or a name from Settings, Theme"}
		}
		st.Theme = tui.NormalizeTheme(value)
	default:
		return &exitError{ExitUsage, "unknown setting; supported: auth-encrypt, key-type, theme"}
	}
	if err := d.Settings.Save(st); err != nil {
		return &exitError{ExitOther, "could not save settings"}
	}
	if !d.opts.quiet {
		d.printf("%s set\n", key)
	}
	return nil
}
