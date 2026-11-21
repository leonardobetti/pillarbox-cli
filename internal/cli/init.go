package cli

import (
	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func newInitCmd(d *Deps) *cobra.Command {
	var mode string
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Create the keystore (first-run setup)",
		Args:  exactArgs(0, "usage: pillarbox init [--mode MODE] [--force]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runInit(mode, force)
		},
	}
	c.Flags().StringVar(&mode, "mode", string(keystore.ModePassword), "unlock mode: password, pin, password+2fa, pin+2fa")
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing keystore")
	return c
}

// runInit implements PRD 7.1: secret read twice, device secret for PIN modes,
// Argon2id+HKDF KEK, identity and TOTP seed wrapped under the KEK, keystore
// saved atomically, recovery key shown once.
func (d *Deps) runInit(modeStr string, force bool) error {
	m := keystore.Mode(modeStr)
	if !m.Valid() {
		return &exitError{ExitUsage, "invalid mode; want password, pin, password+2fa or pin+2fa"}
	}
	exists, err := d.Store.Exists()
	if err != nil {
		return &exitError{ExitOther, "cannot access keystore"}
	}
	if exists && !force {
		return &exitError{ExitOther, "keystore already exists; use --force to overwrite"}
	}

	secret, err := d.readSecret(true)
	if err != nil {
		return err
	}
	if err := auth.ValidateSecret(m, secret); err != nil {
		return &exitError{ExitUsage, "invalid secret: " + err.Error()}
	}

	var devSecret []byte
	if m.HasDeviceSecret() {
		devSecret, _, err = d.DevStore.LoadOrCreate()
		if err != nil {
			return &exitError{ExitOther, "cannot write device secret"}
		}
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return &exitError{ExitOther, "cannot generate identity"}
	}

	var seed []byte
	if m.Has2FA() {
		seed, uri, err := d.TOTP.GenerateSeed()
		if err != nil {
			return &exitError{ExitOther, "cannot generate TOTP seed"}
		}
		d.println("2FA URI: " + uri)
		code, err := d.readTOTP()
		if err != nil {
			return err
		}
		ok, _, verr := d.TOTP.Verify(seed, code, -1)
		if verr != nil || !ok {
			return &exitError{ExitAuth, "authentication failed; check the 2FA code"}
		}
	}

	ks, err := auth.NewInitializer(d.KDF, d.Wrapper).Initialize(
		m, identity.Recipient().String(), []byte(identity.String()), secret, devSecret, seed, keystore.DefaultArgon2Params)
	if err != nil {
		return &exitError{ExitOther, "cannot build keystore"}
	}
	if err := d.Store.Save(ks); err != nil {
		return &exitError{ExitOther, "cannot write keystore"}
	}

	if !d.opts.quiet {
		d.printf("keystore created at %s\n", d.Store.Path())
	}
	d.printf("recovery key (shown once): %s\n", identity.String())
	return nil
}
