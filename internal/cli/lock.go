package cli

import (
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
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
// from Settings (asked in the TUI when unset), the secret wraps the per-file
// key and original filename, and the header is embedded in the .pbx output.
func (d *Deps) runLock(path, out string, removeOriginal, force bool) error {
	mode, err := d.keyType()
	if err != nil {
		return err
	}
	ks, recovery, err := d.buildFileKey(mode, filepath.Base(path))
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
		d.printf("%s", keystore.FormatEncryptSuccess(locked, mode, removeOriginal, recovery))
	}
	return nil
}

// runUnlock decrypts a .pbx file using its embedded key: authenticate,
// persist the new TOTP step when needed, then stream through vault.Unlock.
func (d *Deps) runUnlock(src, out string, force bool) error {
	if !strings.HasSuffix(src, ".pbx") {
		return &exitError{ExitUsage, "unlock accepts a .pbx file only"}
	}
	ks, err := d.loadFileKey(src)
	if err != nil {
		return err
	}
	res, err := d.authenticate(ks)
	if err != nil {
		return err
	}
	if ks.Mode.Has2FA() {
		step := res.NewTOTPStep
		ks.LastTOTPStep = &step
		if err := d.Vault.SaveKey(src, ks); err != nil {
			d.warn("warning: could not persist the TOTP step")
		}
	}
	id, err := age.ParseX25519Identity(string(res.Identity))
	if err != nil {
		return &exitError{ExitOther, "internal error: stored identity is invalid"}
	}
	dst, err := d.Vault.Unlock(src, id, vault.UnlockOptions{
		Out:          out,
		OriginalName: res.OriginalName,
		Force:        force,
	})
	if err != nil {
		return mapVaultErr(err)
	}
	if !d.opts.quiet {
		d.printf("%s", keystore.FormatDecryptSuccess(dst))
	}
	return nil
}
