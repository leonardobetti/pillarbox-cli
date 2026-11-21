package cli

import (
	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

func newLockCmd(d *Deps) *cobra.Command {
	var out string
	var removeOriginal, force bool
	c := &cobra.Command{
		Use:     "lock <path>",
		Aliases: []string{"encrypt"},
		Short:   "Encrypt a file",
		Args:    exactArgs(1, "usage: pillarbox lock <path> [-o OUT] [--remove-original] [--force]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runLock(args[0], out, removeOriginal, force)
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output path")
	c.Flags().BoolVar(&removeOriginal, "remove-original", false, "remove the original after locking")
	c.Flags().BoolVar(&force, "force", false, "overwrite existing output")
	return c
}

func newUnlockCmd(d *Deps) *cobra.Command {
	var out string
	var force bool
	c := &cobra.Command{
		Use:     "unlock <file.pbx>",
		Aliases: []string{"decrypt"},
		Short:   "Decrypt a .pbx file",
		Args:    exactArgs(1, "usage: pillarbox unlock <file.pbx> [-o OUT] [--force]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runUnlock(args[0], out, force)
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "output path")
	c.Flags().BoolVar(&force, "force", false, "overwrite existing output")
	return c
}

// runLock implements PRD 7.3: authenticate first when gate-encrypt is on,
// then stream through vault.Lock.
func (d *Deps) runLock(path, out string, removeOriginal, force bool) error {
	ks, err := d.loadKeystore()
	if err != nil {
		return err
	}
	if ks.Policy.GateEncrypt {
		if _, _, err := d.authenticate(ks); err != nil {
			return err
		}
	}
	dst, err := d.Vault.Lock(path, ks.Recipient, vault.LockOptions{
		Out:            out,
		RemoveOriginal: removeOriginal,
		Force:          force,
	})
	if err != nil {
		return mapVaultErr(err)
	}
	if !d.opts.quiet {
		d.println(dst)
	}
	return nil
}

// runUnlock implements PRD 7.4: authenticate, persist the new TOTP step, then
// stream through vault.Unlock.
func (d *Deps) runUnlock(src, out string, force bool) error {
	ks, err := d.loadKeystore()
	if err != nil {
		return err
	}
	identityBytes, newStep, err := d.authenticate(ks)
	if err != nil {
		return err
	}
	if ks.Mode.Has2FA() {
		ks.LastTOTPStep = &newStep
		if err := d.Store.Save(ks); err != nil {
			d.warn("warning: could not persist the TOTP step")
		}
	}
	id, err := age.ParseX25519Identity(string(identityBytes))
	if err != nil {
		return &exitError{ExitOther, "internal error: stored identity is invalid"}
	}
	dst, err := d.Vault.Unlock(src, id, vault.UnlockOptions{Out: out, Force: force})
	if err != nil {
		return mapVaultErr(err)
	}
	if !d.opts.quiet {
		d.println(dst)
	}
	return nil
}
