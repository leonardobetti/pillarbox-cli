package cli

import (
	"strings"

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

// runLock encrypts a single file with its own fresh key. The key type comes
// from Settings (asked in the TUI when unset), the secret unwraps the per-file
// key, and the wrapped key is stored next to the output as <file>.pbx.key.
func (d *Deps) runLock(path, out string, removeOriginal, force bool) error {
	mode, err := d.keyType()
	if err != nil {
		return err
	}
	ks, recovery, err := d.buildFileKey(mode)
	if err != nil {
		return err
	}
	locked, err := d.Vault.Lock(path, ks, vault.LockOptions{
		Out:            out,
		RemoveOriginal: removeOriginal,
		Force:          force,
	})
	if err != nil {
		return mapVaultErr(err)
	}
	if !d.opts.quiet {
		d.println(locked)
		d.printf("recovery key for this file (shown once): %s\n", recovery)
	}
	return nil
}

// runUnlock decrypts a .pbx file with its own key from the sidecar
// <file>.pbx.key: authenticate against the sidecar, persist the new TOTP
// step, then stream through vault.Unlock.
func (d *Deps) runUnlock(src, out string, force bool) error {
	if !strings.HasSuffix(src, ".pbx") {
		return &exitError{ExitUsage, "unlock accepts a .pbx file only"}
	}
	ks, err := d.loadFileKey(src)
	if err != nil {
		return err
	}
	identityBytes, newStep, err := d.authenticate(ks)
	if err != nil {
		return err
	}
	if ks.Mode.Has2FA() {
		ks.LastTOTPStep = &newStep
		if err := d.Vault.SaveKey(src, ks); err != nil {
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
